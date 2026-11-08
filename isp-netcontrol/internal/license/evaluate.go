package license

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/justinthoms/my-dns/isp-netcontrol/internal/clock"
	"github.com/justinthoms/my-dns/shared/licensecore"
)

// trusted returns built-in keys plus keys endorsed through a valid chain.
func (m *Manager) trusted(ctx context.Context) licensecore.TrustedKeys {
	keys := m.builtin.Clone()
	keys.AcceptEndorsements(m.storedEndorsements(ctx))
	return keys
}

func (m *Manager) storedEndorsements(ctx context.Context) []*licensecore.Envelope {
	var raw []byte
	_ = m.db.QueryRow(ctx, `SELECT endorsements FROM license_state WHERE id=1`).Scan(&raw)
	var chain []*licensecore.Envelope
	_ = json.Unmarshal(raw, &chain)
	return chain
}

// mergeEndorsements stores the endorsements that extend the trust chain.
func (m *Manager) mergeEndorsements(ctx context.Context, chain []*licensecore.Envelope) error {
	if len(chain) == 0 {
		return nil
	}
	existing := m.storedEndorsements(ctx)
	seen := map[string]bool{}
	for _, e := range existing {
		seen[e.Signature] = true
	}
	keys := m.builtin.Clone()
	keys.AcceptEndorsements(append(append([]*licensecore.Envelope{}, existing...), chain...))
	changed := false
	for _, e := range chain {
		if seen[e.Signature] {
			continue
		}
		var ke licensecore.KeyEndorsement
		if keys.Verify(e, licensecore.TypeKeyEndorsement, &ke) == nil {
			existing = append(existing, e)
			seen[e.Signature] = true
			changed = true
		}
	}
	if !changed {
		return nil
	}
	raw, _ := json.Marshal(existing)
	_, err := m.db.Exec(ctx, `UPDATE license_state SET endorsements=$1 WHERE id=1`, raw)
	return err
}

// effectiveNow advances the high-water mark and returns max(now, high-water).
// A clock that runs behind the high-water mark is recorded as tampering.
func (m *Manager) effectiveNow(ctx context.Context) (time.Time, bool, error) {
	now := clock.Now().UTC()
	var p persisted
	err := m.db.QueryRow(ctx, `SELECT trial_started_at, high_water, install_id, mac FROM license_state WHERE id=1`).
		Scan(&p.TrialStartedAt, &p.HighWater, &p.InstallID, &p.MAC)
	if err != nil {
		return now, false, err
	}
	dirty := false
	if !m.macOK(p) {
		// Edited while running: treat as tampering, end the trial.
		m.addTamper(ctx, "state_database_modified", "license state in the database changed outside ISP NetControl")
		p.TrialStartedAt, dirty = expiredTrialStart, true
	}
	switch fp, found, ferr := m.readFile(); {
	case !found:
		dirty = true // deleted while running: restore it
	case ferr != nil || !m.macOK(*fp):
		m.addTamper(ctx, "state_file_modified", "license state file changed outside ISP NetControl")
		p.TrialStartedAt, dirty = expiredTrialStart, true
	case fp.TrialStartedAt.Before(p.TrialStartedAt) || fp.HighWater.After(p.HighWater):
		// A valid but different copy (e.g. database restored from an old
		// backup): keep the earliest trial start and the latest time seen.
		if fp.TrialStartedAt.Before(p.TrialStartedAt) {
			p.TrialStartedAt = fp.TrialStartedAt
		}
		if fp.HighWater.After(p.HighWater) {
			p.HighWater = fp.HighWater
		}
		dirty = true
	}
	if dirty {
		if err := m.save(ctx, p); err != nil {
			return now, false, err
		}
		if err := m.flushTamper(ctx); err != nil {
			return now, false, err
		}
	}
	if now.Before(p.HighWater.Add(-rollbackTolerance)) {
		if !m.inRollback {
			m.addTamper(ctx, "clock_rollback", fmt.Sprintf("system clock (%s) is behind the latest time already seen (%s)",
				now.Format(time.RFC3339), p.HighWater.Format(time.RFC3339)))
		}
		m.inRollback = true
		return p.HighWater, true, nil
	}
	m.inRollback = false
	if now.After(p.HighWater) {
		p.HighWater = now
		if err := m.save(ctx, p); err != nil {
			return now, false, err
		}
	}
	if now.Before(p.HighWater) {
		return p.HighWater, false, nil
	}
	return now, false, nil
}

func daysLeft(now, end time.Time) int {
	d := end.Sub(now)
	if d <= 0 {
		return 0
	}
	return int((d + 24*time.Hour - time.Second) / (24 * time.Hour))
}

// Evaluate recomputes the license state.
func (m *Manager) Evaluate(ctx context.Context) (State, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.evaluateLocked(ctx)
}

func (m *Manager) evaluateLocked(ctx context.Context) (State, error) {
	now, rollback, err := m.effectiveNow(ctx)
	if err != nil {
		return m.cur, err
	}
	var (
		trialStart  time.Time
		licenseText string
		revRaw      []byte
		syncRaw     []byte
	)
	if err := m.db.QueryRow(ctx, `SELECT trial_started_at, license_text, revoked, last_sync FROM license_state WHERE id=1`).
		Scan(&trialStart, &licenseText, &revRaw, &syncRaw); err != nil {
		return m.cur, err
	}
	keys := m.trusted(ctx)
	st := State{
		HardwareID: m.hwid, EffectiveTime: now, ClockRollback: rollback,
		TrialEndsAt: trialStart.Add(TrialDays * 24 * time.Hour), Features: []string{},
		Tamper: m.tamperEvents(ctx),
	}
	for kid := range keys {
		st.TrustedKeyIDs = append(st.TrustedKeyIDs, kid)
	}
	if len(revRaw) > 0 && string(revRaw) != "null" {
		st.Revocation = &Revocation{}
		_ = json.Unmarshal(revRaw, st.Revocation)
	}
	if len(syncRaw) > 0 && string(syncRaw) != "null" {
		st.LastSync = &SyncResult{}
		_ = json.Unmarshal(syncRaw, st.LastSync)
	}

	if licenseText != "" {
		env, _, err := licensecore.DecodeBundle(licenseText)
		var lic *licensecore.License
		if err == nil {
			lic, err = keys.VerifyLicense(env, licensecore.ProductNetControl, m.hwid, now)
		}
		if lic != nil {
			st.LicenseID, st.Serial, st.Customer, st.Edition, st.MaxClients = lic.LicenseID, lic.Serial, lic.Customer, lic.Edition, lic.MaxClients
			exp := lic.ExpiresAt
			st.ExpiresAt = &exp
			st.DaysLeft = daysLeft(now, exp)
		}
		switch {
		case err == nil && st.Revocation != nil && st.Revocation.LicenseID == lic.LicenseID && st.Revocation.Serial >= lic.Serial:
			st.Mode = ModeRevoked
			st.Message = "This license was revoked by the vendor: " + st.Revocation.Reason
		case err == nil:
			st.Mode = ModeLicensed
			st.Features = append(st.Features, lic.Features...)
			st.Message = fmt.Sprintf("Licensed to %s until %s", lic.Customer, lic.ExpiresAt.Format("2006-01-02"))
		case errors.Is(err, licensecore.ErrExpired):
			st.Mode = ModeLicenseExpired
			st.Message = "The license has expired. Renew it with your vendor."
		default:
			st.Mode = ModeInvalid
			st.Message = "The installed license is not valid on this server: " + err.Error()
		}
	} else if now.Before(st.TrialEndsAt) {
		st.Mode = ModeTrial
		st.Features = append(st.Features, licensecore.AllFeatures...)
		st.DaysLeft = daysLeft(now, st.TrialEndsAt)
		st.Message = fmt.Sprintf("Trial: %d day(s) left. Activate a license to keep using ISP NetControl.", st.DaysLeft)
	} else {
		st.Mode = ModeTrialExpired
		st.Message = "The trial has ended. Activate a license to re-enable filtering and firewall management."
	}
	if rollback {
		st.Message += " Warning: the system clock is behind; check NTP."
	}
	m.cur = st
	return st, nil
}

// Current returns the last evaluated state without touching the database.
func (m *Manager) Current() State {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.cur
}

// Install verifies and stores a license file (offline activation, or the
// result of online activation / renewal).
func (m *Manager) Install(ctx context.Context, text string) (State, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.installLocked(ctx, text)
}

func (m *Manager) installLocked(ctx context.Context, text string) (State, error) {
	env, chain, err := licensecore.DecodeBundle(text)
	if err != nil {
		return m.cur, fmt.Errorf("this is not a valid license file: %w", err)
	}
	if err := m.mergeEndorsements(ctx, chain); err != nil {
		return m.cur, err
	}
	now, _, err := m.effectiveNow(ctx)
	if err != nil {
		return m.cur, err
	}
	lic, err := m.trusted(ctx).VerifyLicense(env, licensecore.ProductNetControl, m.hwid, now)
	if err != nil {
		return m.cur, fmt.Errorf("license rejected: %w", err)
	}
	var revRaw []byte
	_ = m.db.QueryRow(ctx, `SELECT revoked FROM license_state WHERE id=1`).Scan(&revRaw)
	if len(revRaw) > 0 && string(revRaw) != "null" {
		var rev Revocation
		if json.Unmarshal(revRaw, &rev) == nil && rev.LicenseID == lic.LicenseID && rev.Serial >= lic.Serial {
			return m.cur, errors.New("license rejected: this license was revoked by the vendor")
		}
	}
	armored, err := licensecore.EncodeArmored(env, licensecore.PEMBlockLicense)
	if err != nil {
		return m.cur, err
	}
	if _, err := m.db.Exec(ctx, `UPDATE license_state SET license_text=$1, revoked=CASE WHEN revoked->>'license_id' = $2 AND (revoked->>'serial')::int < $3 THEN NULL ELSE revoked END WHERE id=1`,
		armored, lic.LicenseID, lic.Serial); err != nil {
		return m.cur, err
	}
	return m.evaluateLocked(ctx)
}

func normaliseURL(u string) string { return strings.TrimRight(strings.TrimSpace(u), "/") }
