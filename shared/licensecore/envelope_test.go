package licensecore

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

func newKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return priv
}

func sampleLicense() License {
	now := time.Now().UTC().Truncate(time.Second)
	return License{
		LicenseID: "lic-1", Serial: 1, Product: ProductNetControl, Customer: "ACME ISP",
		Edition: "standard", Features: AllFeatures, HardwareID: "hw-1",
		IssuedAt: now, ValidFrom: now, ExpiresAt: now.AddDate(1, 0, 0),
	}
}

func TestSignVerifyRoundTrip(t *testing.T) {
	priv := newKey(t)
	trusted := TrustedKeys{}
	trusted.Add(priv.Public().(ed25519.PublicKey))
	lic := sampleLicense()
	env, err := Sign(priv, TypeLicense, lic)
	if err != nil {
		t.Fatal(err)
	}
	got, err := trusted.VerifyLicense(env, ProductNetControl, "hw-1", time.Now())
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if got.Customer != "ACME ISP" || !got.HasFeature(FeatureFirewall) {
		t.Fatalf("payload mismatch: %+v", got)
	}
}

func TestTamperedPayloadRejected(t *testing.T) {
	priv := newKey(t)
	trusted := TrustedKeys{}
	trusted.Add(priv.Public().(ed25519.PublicKey))
	env, _ := Sign(priv, TypeLicense, sampleLicense())

	// Re-encode the payload with a later expiry date but keep the signature.
	raw, _ := b64.DecodeString(env.Payload)
	var m map[string]any
	_ = json.Unmarshal(raw, &m)
	m["expires_at"] = time.Now().AddDate(50, 0, 0).Format(time.RFC3339)
	raw, _ = json.Marshal(m)
	env.Payload = b64.EncodeToString(raw)

	var lic License
	if err := trusted.Verify(env, TypeLicense, &lic); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("want ErrBadSignature, got %v", err)
	}
}

func TestForgedKeyRejected(t *testing.T) {
	real, forger := newKey(t), newKey(t)
	trusted := TrustedKeys{}
	trusted.Add(real.Public().(ed25519.PublicKey))

	env, _ := Sign(forger, TypeLicense, sampleLicense())
	var lic License
	if err := trusted.Verify(env, TypeLicense, &lic); !errors.Is(err, ErrUnknownKey) {
		t.Fatalf("want ErrUnknownKey, got %v", err)
	}
	// Claiming the trusted key ID does not help: the signature fails.
	env.KeyID = KeyID(real.Public().(ed25519.PublicKey))
	if err := trusted.Verify(env, TypeLicense, &lic); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("want ErrBadSignature, got %v", err)
	}
}

func TestTypeConfusionRejected(t *testing.T) {
	priv := newKey(t)
	trusted := TrustedKeys{}
	trusted.Add(priv.Public().(ed25519.PublicKey))
	env, _ := Sign(priv, TypeStatus, StatusReport{LicenseID: "x"})
	env.Type = TypeLicense // signature covers the type
	var lic License
	if err := trusted.Verify(env, TypeLicense, &lic); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("want ErrBadSignature, got %v", err)
	}
}

func TestKeyRotationOldLicenseStillValid(t *testing.T) {
	oldKey, newK := newKey(t), newKey(t)
	trusted := TrustedKeys{}
	trusted.Add(oldKey.Public().(ed25519.PublicKey))
	trusted.Add(newK.Public().(ed25519.PublicKey))
	oldEnv, _ := Sign(oldKey, TypeLicense, sampleLicense())
	newEnv, _ := Sign(newK, TypeLicense, sampleLicense())
	if oldEnv.KeyID == newEnv.KeyID {
		t.Fatal("key IDs should differ")
	}
	for _, e := range []*Envelope{oldEnv, newEnv} {
		if _, err := trusted.VerifyLicense(e, ProductNetControl, "hw-1", time.Now()); err != nil {
			t.Fatalf("verify %s: %v", e.KeyID, err)
		}
	}
}

func TestClaimsChecks(t *testing.T) {
	priv := newKey(t)
	trusted := TrustedKeys{}
	trusted.Add(priv.Public().(ed25519.PublicKey))
	env, _ := Sign(priv, TypeLicense, sampleLicense())
	if _, err := trusted.VerifyLicense(env, ProductNetControl, "other-hw", time.Now()); !errors.Is(err, ErrWrongHardware) {
		t.Fatalf("want ErrWrongHardware, got %v", err)
	}
	if _, err := trusted.VerifyLicense(env, "other-product", "hw-1", time.Now()); !errors.Is(err, ErrWrongProduct) {
		t.Fatalf("want ErrWrongProduct, got %v", err)
	}
	if _, err := trusted.VerifyLicense(env, ProductNetControl, "hw-1", time.Now().AddDate(2, 0, 0)); !errors.Is(err, ErrExpired) {
		t.Fatalf("want ErrExpired, got %v", err)
	}
}

func TestStatusReplayRejected(t *testing.T) {
	priv := newKey(t)
	trusted := TrustedKeys{}
	trusted.Add(priv.Public().(ed25519.PublicKey))
	env, _ := Sign(priv, TypeStatus, StatusReport{LicenseID: "lic-1", HardwareID: "hw-1", Nonce: "n1", Status: StatusActive})
	if _, err := trusted.VerifyStatus(env, "lic-1", "hw-1", "n1"); err != nil {
		t.Fatalf("fresh report: %v", err)
	}
	if _, err := trusted.VerifyStatus(env, "lic-1", "hw-1", "n2"); err == nil {
		t.Fatal("replayed report accepted")
	}
}

func TestArmorRoundTrip(t *testing.T) {
	priv := newKey(t)
	pub := priv.Public().(ed25519.PublicKey)
	env, _ := Sign(priv, TypeLicense, sampleLicense())
	text, err := EncodeArmored(env, PEMBlockLicense)
	if err != nil || !strings.Contains(text, "BEGIN "+PEMBlockLicense) {
		t.Fatalf("armor: %v %q", err, text)
	}
	back, err := DecodeArmored(text, PEMBlockLicense)
	if err != nil || back.Signature != env.Signature {
		t.Fatalf("dearmor: %v", err)
	}
	keys, err := ParsePublicKeys(EncodePublicKey(pub) + EncodePublicKey(newKey(t).Public().(ed25519.PublicKey)))
	if err != nil || len(keys) != 2 {
		t.Fatalf("parse keys: %v %d", err, len(keys))
	}
}

func TestEndorsementChain(t *testing.T) {
	k1, k2, k3, rogue := newKey(t), newKey(t), newKey(t), newKey(t)
	pub := func(k ed25519.PrivateKey) ed25519.PublicKey { return k.Public().(ed25519.PublicKey) }
	e12, _ := Endorse(k1, pub(k2))
	e23, _ := Endorse(k2, pub(k3))
	eRogue, _ := Endorse(rogue, pub(rogue))
	trusted := TrustedKeys{}
	trusted.Add(pub(k1))
	// Out of order on purpose; the rogue self-endorsement must be ignored.
	added := trusted.AcceptEndorsements([]*Envelope{e23, eRogue, e12})
	if len(added) != 2 || len(trusted) != 3 {
		t.Fatalf("added %v, trusted %d", added, len(trusted))
	}
	if _, ok := trusted[KeyID(pub(rogue))]; ok {
		t.Fatal("rogue key accepted")
	}
	env, _ := Sign(k3, TypeLicense, sampleLicense())
	if _, err := trusted.VerifyLicense(env, ProductNetControl, "hw-1", time.Now()); err != nil {
		t.Fatalf("license from endorsed key: %v", err)
	}
}
