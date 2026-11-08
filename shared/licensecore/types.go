package licensecore

import (
	"errors"
	"fmt"
	"time"
)

// ProductNetControl is the product code ISP NetControl licenses carry.
const ProductNetControl = "isp-netcontrol"

// Status values reported by the License Manager.
const (
	StatusActive  = "active"
	StatusRevoked = "revoked"
	StatusExpired = "expired"
	StatusUnknown = "unknown"
)

// License is the signed payload of a license file.
type License struct {
	LicenseID  string    `json:"license_id"`
	Serial     int       `json:"serial"` // increases each time the license is re-issued (renewal, migration)
	Product    string    `json:"product"`
	Customer   string    `json:"customer"`
	Edition    string    `json:"edition"`
	Features   []string  `json:"features"`
	MaxClients int       `json:"max_clients"` // 0 = unlimited
	HardwareID string    `json:"hardware_id"`
	IssuedAt   time.Time `json:"issued_at"`
	ValidFrom  time.Time `json:"valid_from"`
	ExpiresAt  time.Time `json:"expires_at"`
}

// StatusReport is the signed answer to a status sync. It echoes the caller's
// nonce so that an old answer (for example an "active" status captured before
// a revocation) cannot be replayed.
type StatusReport struct {
	LicenseID  string    `json:"license_id"`
	HardwareID string    `json:"hardware_id"`
	Nonce      string    `json:"nonce"`
	Status     string    `json:"status"`
	Reason     string    `json:"reason,omitempty"`
	CheckedAt  time.Time `json:"checked_at"`
	Serial     int       `json:"serial"`
	License    *Envelope `json:"license,omitempty"` // current license when its serial is newer than the caller's
}

var (
	ErrWrongProduct  = errors.New("license is for a different product")
	ErrWrongHardware = errors.New("license is bound to different hardware")
	ErrNotYetValid   = errors.New("license is not valid yet")
	ErrExpired       = errors.New("license has expired")
)

// Check validates the license claims against the product, the hardware
// fingerprint and the trusted time. The signature must already be verified.
func (l *License) Check(product, hardwareID string, now time.Time) error {
	if l.LicenseID == "" || l.ExpiresAt.IsZero() {
		return ErrMalformed
	}
	if l.Product != product {
		return ErrWrongProduct
	}
	if l.HardwareID != hardwareID {
		return ErrWrongHardware
	}
	if now.Before(l.ValidFrom.Add(-5 * time.Minute)) {
		return ErrNotYetValid
	}
	if !now.Before(l.ExpiresAt) {
		return fmt.Errorf("%w on %s", ErrExpired, l.ExpiresAt.UTC().Format("2006-01-02"))
	}
	return nil
}

// HasFeature reports whether the license grants feature f.
func (l *License) HasFeature(f string) bool {
	for _, x := range l.Features {
		if x == f || x == "*" {
			return true
		}
	}
	return false
}

// VerifyLicense verifies the signature and claims of a license envelope.
func (t TrustedKeys) VerifyLicense(env *Envelope, product, hardwareID string, now time.Time) (*License, error) {
	var lic License
	if err := t.Verify(env, TypeLicense, &lic); err != nil {
		return nil, err
	}
	if err := lic.Check(product, hardwareID, now); err != nil {
		return &lic, err
	}
	return &lic, nil
}

// VerifyStatus verifies a status report and checks it answers this request.
func (t TrustedKeys) VerifyStatus(env *Envelope, licenseID, hardwareID, nonce string) (*StatusReport, error) {
	var st StatusReport
	if err := t.Verify(env, TypeStatus, &st); err != nil {
		return nil, err
	}
	if st.Nonce != nonce || st.LicenseID != licenseID || st.HardwareID != hardwareID {
		return nil, errors.New("status report does not answer this request (replayed or mismatched)")
	}
	return &st, nil
}

// Feature names understood by ISP NetControl.
const (
	FeatureDNSFiltering = "dns-filtering"
	FeatureFirewall     = "firewall"
	FeatureQueryLog     = "query-log"
)

// AllFeatures lists every feature, in display order.
var AllFeatures = []string{FeatureDNSFiltering, FeatureFirewall, FeatureQueryLog}
