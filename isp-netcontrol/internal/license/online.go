package license

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/justinthoms/my-dns/isp-netcontrol/internal/clock"
	"github.com/justinthoms/my-dns/shared/authkit"
	"github.com/justinthoms/my-dns/shared/licensecore"
)

func (m *Manager) post(ctx context.Context, serverURL, path string, body any, out any) error {
	serverURL = normaliseURL(serverURL)
	if serverURL == "" {
		return errors.New("no license server URL is configured")
	}
	raw, _ := json.Marshal(body)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, serverURL+path, bytes.NewReader(raw))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := m.http.Do(req)
	if err != nil {
		return fmt.Errorf("cannot reach the license server: %w", err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		var e struct {
			Error string `json:"error"`
			Code  string `json:"code"`
		}
		if json.Unmarshal(data, &e) == nil && e.Error != "" {
			return &ServerError{Status: resp.StatusCode, Code: e.Code, Message: e.Error}
		}
		return fmt.Errorf("license server answered HTTP %d", resp.StatusCode)
	}
	return json.Unmarshal(data, out)
}

// ServerError is an error reported by the License Manager.
type ServerError struct {
	Status  int
	Code    string
	Message string
}

func (e *ServerError) Error() string { return "license server: " + e.Message }

// ActivateOnline exchanges a license key for a license file bound to this
// server.
func (m *Manager) ActivateOnline(ctx context.Context, serverURL, licenseKey, version string) (State, error) {
	host, _ := os.Hostname()
	var resp struct {
		License  string                  `json:"license"`
		Keychain []*licensecore.Envelope `json:"keychain"`
	}
	err := m.post(ctx, serverURL, "/api/v1/activate", map[string]string{
		"license_key": licenseKey, "hardware_id": m.hwid, "hostname": host, "version": version,
	}, &resp)
	if err != nil {
		return m.Current(), err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.mergeEndorsements(ctx, resp.Keychain); err != nil {
		return m.cur, err
	}
	return m.installLocked(ctx, resp.License)
}

// Sync asks the License Manager for the license's current status. Results:
// renewed licenses are installed, revocations and hardware releases are
// recorded and take effect immediately.
func (m *Manager) Sync(ctx context.Context, serverURL string) (st State, err error) {
	cur := m.Current()
	if cur.LicenseID == "" {
		return cur, errors.New("no license is installed")
	}
	nonce := authkit.RandomToken(24)
	var resp struct {
		Status   *licensecore.Envelope   `json:"status"`
		Keychain []*licensecore.Envelope `json:"keychain"`
	}
	err = m.post(ctx, serverURL, "/api/v1/status", map[string]any{
		"license_id": cur.LicenseID, "hardware_id": m.hwid, "nonce": nonce, "serial": cur.Serial,
	}, &resp)

	m.mu.Lock()
	defer m.mu.Unlock()
	result := SyncResult{At: clock.Now().UTC()}
	defer func() {
		raw, _ := json.Marshal(result)
		_, _ = m.db.Exec(ctx, `UPDATE license_state SET last_sync=$1 WHERE id=1`, raw)
		_, _ = m.evaluateLocked(ctx)
		st = m.cur // report the state including this sync
	}()
	if err != nil {
		result.Message = err.Error()
		return m.cur, err
	}
	if err := m.mergeEndorsements(ctx, resp.Keychain); err != nil {
		result.Message = err.Error()
		return m.cur, err
	}
	report, err := m.trusted(ctx).VerifyStatus(resp.Status, cur.LicenseID, m.hwid, nonce)
	if err != nil {
		result.Message = "status answer rejected: " + err.Error()
		return m.cur, errors.New(result.Message)
	}
	result.OK, result.Status = true, report.Status
	switch report.Status {
	case licensecore.StatusActive:
		result.Message = "license is active"
		if report.License != nil {
			text, err := licensecore.EncodeArmored(report.License, licensecore.PEMBlockLicense)
			if err == nil {
				_, err = m.installLocked(ctx, text)
			}
			if err != nil {
				result.OK = false
				result.Message = "updated license could not be installed: " + err.Error()
				return m.cur, errors.New(result.Message)
			}
			result.Message = "an updated license was received and installed"
		}
	case licensecore.StatusRevoked:
		rev := Revocation{LicenseID: report.LicenseID, Serial: report.Serial, Reason: report.Reason, At: report.CheckedAt, Evidence: resp.Status}
		raw, _ := json.Marshal(rev)
		if _, err := m.db.Exec(ctx, `UPDATE license_state SET revoked=$1 WHERE id=1`, raw); err != nil {
			return m.cur, err
		}
		result.Message = "license revoked: " + report.Reason
		log.Printf("license: revoked by the License Manager: %s", report.Reason)
	case licensecore.StatusExpired:
		result.Message = "license server reports the license as expired"
	default:
		result.Message = "license server does not recognise this license: " + report.Reason
	}
	return m.cur, nil
}

// Settings supplies the current sync configuration to Run.
type Settings func(ctx context.Context) (serverURL string, syncEnabled bool)

// Run re-evaluates the license every minute and syncs on the given interval.
// onChange is called whenever the mode or the enabled features change.
func (m *Manager) Run(ctx context.Context, interval time.Duration, settings Settings, onChange func(State)) {
	last := m.Current()
	lastSync := time.Time{}
	tick := time.NewTicker(time.Minute)
	defer tick.Stop()
	for {
		if url, enabled := settings(ctx); enabled && url != "" && m.Current().LicenseID != "" && time.Since(lastSync) >= interval {
			lastSync = time.Now()
			if _, err := m.Sync(ctx, url); err != nil {
				log.Printf("license: status sync failed: %v", err)
			}
		}
		st, err := m.Evaluate(ctx)
		if err != nil {
			log.Printf("license: evaluate: %v", err)
		} else if st.Mode != last.Mode || fmt.Sprint(st.Features) != fmt.Sprint(last.Features) {
			log.Printf("license: mode %s -> %s", last.Mode, st.Mode)
			last = st
			onChange(st)
		}
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}
