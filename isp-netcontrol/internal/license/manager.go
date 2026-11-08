// Package license enforces ISP NetControl licensing: the trial period,
// installed license files, online/offline activation, status sync with the
// License Manager, and detection of clock and state tampering.
//
// Tamper resistance model: the trial start and a "high-water mark" of the
// latest time ever seen are stored twice (database and state file), each with
// an HMAC. The trial start is the earliest valid copy, the high-water mark the
// latest. Licenses and the trial are checked against max(now, high-water), so
// setting the clock back never extends anything. Someone with root on the
// server can still delete both copies (a full reinstall); that is detected only
// as a fresh install. See docs/LICENSING.md.
package license

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/justinthoms/my-dns/isp-netcontrol/internal/clock"
	"github.com/justinthoms/my-dns/shared/authkit"
	"github.com/justinthoms/my-dns/shared/licensecore"
)

const (
	// TrialDays is fixed in the binary on purpose: it is not configurable.
	TrialDays = 30
	// rollbackTolerance absorbs NTP corrections.
	rollbackTolerance = 10 * time.Minute
	maxTamperEvents   = 50
)

// Modes reported in State.Mode.
const (
	ModeLicensed       = "licensed"
	ModeTrial          = "trial"
	ModeTrialExpired   = "trial_expired"
	ModeLicenseExpired = "license_expired"
	ModeRevoked        = "revoked"
	ModeInvalid        = "invalid"
)

// Schema is the license state table; nc runs it with its migrations.
const Schema = `
CREATE TABLE IF NOT EXISTS license_state (
  id               INT PRIMARY KEY CHECK (id = 1),
  trial_started_at TIMESTAMPTZ NOT NULL,
  high_water       TIMESTAMPTZ NOT NULL,
  install_id       TEXT NOT NULL,
  mac              TEXT NOT NULL,
  tamper           JSONB NOT NULL DEFAULT '[]'::jsonb,
  license_text     TEXT NOT NULL DEFAULT '',
  revoked          JSONB,
  endorsements     JSONB NOT NULL DEFAULT '[]'::jsonb,
  last_sync        JSONB
);`

// TamperEvent records a detected manipulation.
type TamperEvent struct {
	Kind       string    `json:"kind"`
	Detail     string    `json:"detail"`
	DetectedAt time.Time `json:"detected_at"`
}

// Revocation is stored when the License Manager reports a revocation. It
// blocks the license until a newer license (higher serial) is delivered.
type Revocation struct {
	LicenseID string    `json:"license_id"`
	Serial    int       `json:"serial"`
	Reason    string    `json:"reason"`
	At        time.Time `json:"at"`
	Evidence  any       `json:"evidence,omitempty"` // the signed status report
}

// SyncResult describes the last status sync.
type SyncResult struct {
	At      time.Time `json:"at"`
	OK      bool      `json:"ok"`
	Status  string    `json:"status,omitempty"`
	Message string    `json:"message"`
}

// State is the evaluated license situation.
type State struct {
	Mode          string        `json:"mode"`
	Message       string        `json:"message"`
	Features      []string      `json:"features"`
	LicenseID     string        `json:"license_id,omitempty"`
	Serial        int           `json:"serial,omitempty"`
	Customer      string        `json:"customer,omitempty"`
	Edition       string        `json:"edition,omitempty"`
	MaxClients    int           `json:"max_clients"`
	ExpiresAt     *time.Time    `json:"expires_at,omitempty"`
	TrialEndsAt   time.Time     `json:"trial_ends_at"`
	DaysLeft      int           `json:"days_left"`
	HardwareID    string        `json:"hardware_id"`
	EffectiveTime time.Time     `json:"effective_time"`
	ClockRollback bool          `json:"clock_rollback"`
	Tamper        []TamperEvent `json:"tamper_events"`
	Revocation    *Revocation   `json:"revocation,omitempty"`
	LastSync      *SyncResult   `json:"last_sync,omitempty"`
	TrustedKeyIDs []string      `json:"trusted_key_ids"`
}

// Has reports whether a feature is currently enabled.
func (s State) Has(feature string) bool {
	for _, f := range s.Features {
		if f == feature {
			return true
		}
	}
	return false
}

// Options configures a Manager.
type Options struct {
	DB          *pgxpool.Pool
	StateDir    string
	Secret      string // NC_SECRET; keys the state HMAC
	HardwareID  string
	TrustedPEM  string // overrides the built-in keys (unit tests only)
	LMCAFile    string // extra CA for a License Manager with a private certificate
	HTTPTimeout time.Duration
}

// Manager owns license state.
type Manager struct {
	db        *pgxpool.Pool
	stateFile string
	macKey    []byte
	hwid      string
	builtin   licensecore.TrustedKeys
	http      *http.Client

	mu            sync.Mutex
	inRollback    bool
	pendingTamper []TamperEvent // detected before the state row existed
	cur           State
}

// ErrNoTrustedKeys means the binary was built without running
// scripts/set-trusted-keys.sh.
var ErrNoTrustedKeys = errors.New("no License Manager signing key is built into this binary; run scripts/set-trusted-keys.sh and rebuild")

// New creates a Manager and loads (or initialises) the persisted state.
func New(ctx context.Context, o Options) (*Manager, error) {
	pemText := o.TrustedPEM
	if pemText == "" {
		pemText = builtinTrustedKeys
	}
	keys, err := licensecore.ParsePublicKeys(pemText)
	if err != nil {
		return nil, fmt.Errorf("trusted keys: %w", err)
	}
	if len(keys) == 0 {
		return nil, ErrNoTrustedKeys
	}
	if o.Secret == "" {
		return nil, errors.New("NC_SECRET is required")
	}
	if err := os.MkdirAll(o.StateDir, 0o700); err != nil {
		return nil, fmt.Errorf("state dir: %w", err)
	}
	mk := sha256.Sum256([]byte("isp-netcontrol-state-v1\x00" + o.Secret + "\x00" + o.HardwareID))
	timeout := o.HTTPTimeout
	if timeout == 0 {
		timeout = 20 * time.Second
	}
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if o.LMCAFile != "" {
		pool, err := x509.SystemCertPool()
		if err != nil {
			pool = x509.NewCertPool()
		}
		pemCA, err := os.ReadFile(o.LMCAFile)
		if err != nil {
			return nil, fmt.Errorf("NC_LM_CA_FILE: %w", err)
		}
		if !pool.AppendCertsFromPEM(pemCA) {
			return nil, errors.New("NC_LM_CA_FILE contains no certificates")
		}
		tlsCfg.RootCAs = pool
	}
	m := &Manager{
		db:        o.DB,
		stateFile: filepath.Join(o.StateDir, "license.state"),
		macKey:    mk[:],
		hwid:      o.HardwareID,
		builtin:   keys,
		http: &http.Client{Timeout: timeout, Transport: &http.Transport{
			TLSClientConfig: tlsCfg, Proxy: http.ProxyFromEnvironment,
		}},
	}
	if err := m.loadState(ctx); err != nil {
		return nil, err
	}
	if _, err := m.Evaluate(ctx); err != nil {
		return nil, err
	}
	return m, nil
}

// HardwareID returns this server's fingerprint.
func (m *Manager) HardwareID() string { return m.hwid }

// ---- persisted trial / high-water state ---------------------------------

type persisted struct {
	TrialStartedAt time.Time `json:"trial_started_at"`
	HighWater      time.Time `json:"high_water"`
	InstallID      string    `json:"install_id"`
	MAC            string    `json:"mac"`
}

func (m *Manager) mac(p persisted) string {
	h := hmac.New(sha256.New, m.macKey)
	fmt.Fprintf(h, "%d|%d|%s", p.TrialStartedAt.Unix(), p.HighWater.Unix(), p.InstallID)
	return hex.EncodeToString(h.Sum(nil))
}

func (m *Manager) macOK(p persisted) bool {
	return hmac.Equal([]byte(m.mac(p)), []byte(p.MAC))
}

func (m *Manager) readFile() (*persisted, bool, error) {
	raw, err := os.ReadFile(m.stateFile)
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	var p persisted
	if json.Unmarshal(raw, &p) != nil {
		return &p, true, errBadState
	}
	return &p, true, nil
}

var errBadState = errors.New("unparseable state")

func (m *Manager) writeFile(p persisted) error {
	raw, _ := json.MarshalIndent(p, "", "  ")
	tmp := m.stateFile + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, m.stateFile)
}

func (m *Manager) readDB(ctx context.Context) (*persisted, bool, error) {
	var p persisted
	err := m.db.QueryRow(ctx, `SELECT trial_started_at, high_water, install_id, mac FROM license_state WHERE id=1`).
		Scan(&p.TrialStartedAt, &p.HighWater, &p.InstallID, &p.MAC)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	return &p, true, nil
}

func (m *Manager) writeDB(ctx context.Context, p persisted) error {
	_, err := m.db.Exec(ctx, `INSERT INTO license_state(id, trial_started_at, high_water, install_id, mac) VALUES (1,$1,$2,$3,$4)
		ON CONFLICT (id) DO UPDATE SET trial_started_at=$1, high_water=$2, install_id=$3, mac=$4`,
		p.TrialStartedAt, p.HighWater, p.InstallID, p.MAC)
	return err
}

func (m *Manager) save(ctx context.Context, p persisted) error {
	p.TrialStartedAt = p.TrialStartedAt.UTC().Truncate(time.Second)
	p.HighWater = p.HighWater.UTC().Truncate(time.Second)
	p.MAC = m.mac(p)
	if err := m.writeDB(ctx, p); err != nil {
		return err
	}
	return m.writeFile(p)
}

// expiredTrialStart is used when a copy of the state has been tampered with:
// the trial is treated as long over. Tampering never extends a trial.
var expiredTrialStart = time.Unix(0, 0).UTC()

func (m *Manager) loadState(ctx context.Context) error {
	dbP, dbFound, err := m.readDB(ctx)
	if err != nil {
		return err
	}
	fileP, fileFound, ferr := m.readFile()
	if ferr != nil && !errors.Is(ferr, errBadState) {
		return ferr
	}
	now := clock.Now().UTC()
	var copies []persisted
	if dbFound {
		if !m.macOK(*dbP) {
			m.addTamper(ctx, "state_database_modified", "license state in the database failed its integrity check (edited, or restored onto different hardware)")
			dbP.TrialStartedAt = expiredTrialStart
		}
		copies = append(copies, *dbP)
	}
	if fileFound {
		if ferr != nil || !m.macOK(*fileP) {
			m.addTamper(ctx, "state_file_modified", "license state file failed its integrity check (edited, or restored onto different hardware)")
			if ferr != nil {
				fileP = &persisted{HighWater: now}
			}
			fileP.TrialStartedAt = expiredTrialStart
		}
		copies = append(copies, *fileP)
	}
	var p persisted
	switch len(copies) {
	case 0:
		p = persisted{TrialStartedAt: now, HighWater: now, InstallID: authkit.RandomToken(12)}
		log.Printf("license: first start on this server; %d-day trial begins now", TrialDays)
	default:
		p = copies[0]
		for _, c := range copies[1:] {
			if c.TrialStartedAt.Before(p.TrialStartedAt) {
				p.TrialStartedAt = c.TrialStartedAt
			}
			if c.HighWater.After(p.HighWater) {
				p.HighWater = c.HighWater
			}
		}
		if dbFound != fileFound {
			log.Printf("license: one copy of the license state was missing and has been restored from the other")
		}
	}
	if p.InstallID == "" {
		p.InstallID = authkit.RandomToken(12)
	}
	if err := m.save(ctx, p); err != nil {
		return err
	}
	return m.flushTamper(ctx)
}

func (m *Manager) flushTamper(ctx context.Context) error {
	if len(m.pendingTamper) == 0 {
		return nil
	}
	pending := m.pendingTamper
	m.pendingTamper = nil
	events := append(m.tamperEvents(ctx), pending...)
	raw, _ := json.Marshal(events)
	_, err := m.db.Exec(ctx, `UPDATE license_state SET tamper=$1 WHERE id=1`, raw)
	return err
}

// addTamper appends an event (deduplicated by kind within an hour).
func (m *Manager) addTamper(ctx context.Context, kind, detail string) {
	events := m.tamperEvents(ctx)
	now := clock.Now().UTC()
	for _, e := range events {
		if e.Kind == kind && now.Sub(e.DetectedAt) < time.Hour && now.Sub(e.DetectedAt) > -time.Hour {
			return
		}
	}
	events = append(events, TamperEvent{Kind: kind, Detail: detail, DetectedAt: now})
	if len(events) > maxTamperEvents {
		events = events[len(events)-maxTamperEvents:]
	}
	raw, _ := json.Marshal(events)
	// The row may not exist yet on first start; the UPDATE is retried after save.
	if tag, err := m.db.Exec(ctx, `UPDATE license_state SET tamper=$1 WHERE id=1`, raw); err != nil || tag.RowsAffected() == 0 {
		m.pendingTamper = append(m.pendingTamper, events[len(events)-1])
	}
	log.Printf("license: TAMPER DETECTED: %s: %s", kind, detail)
}

func (m *Manager) tamperEvents(ctx context.Context) []TamperEvent {
	var raw []byte
	_ = m.db.QueryRow(ctx, `SELECT tamper FROM license_state WHERE id=1`).Scan(&raw)
	events := []TamperEvent{}
	_ = json.Unmarshal(raw, &events)
	return append(events, m.pendingTamper...)
}
