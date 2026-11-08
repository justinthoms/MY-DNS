package licensecore

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"time"
)

// TypeKeyEndorsement marks a document in which a signing key vouches for its
// successor. When the License Manager rotates keys, it signs the new public
// key with the old one. A product that trusts any key in the chain can then
// verify licenses from the new key without a software update.
const TypeKeyEndorsement = "key-endorsement"

// KeyEndorsement is the payload of an endorsement.
type KeyEndorsement struct {
	PublicKey string    `json:"public_key"` // base64 Ed25519 public key
	KeyID     string    `json:"key_id"`
	IssuedAt  time.Time `json:"issued_at"`
}

// Endorse signs newPub with the current key priv.
func Endorse(priv ed25519.PrivateKey, newPub ed25519.PublicKey) (*Envelope, error) {
	return Sign(priv, TypeKeyEndorsement, KeyEndorsement{
		PublicKey: base64.StdEncoding.EncodeToString(newPub),
		KeyID:     KeyID(newPub),
		IssuedAt:  time.Now().UTC().Truncate(time.Second),
	})
}

// AcceptEndorsements extends t with every key reachable from an already
// trusted key through the chain. Endorsements that do not verify are ignored.
// It returns the IDs of keys that were added.
func (t TrustedKeys) AcceptEndorsements(chain []*Envelope) []string {
	var added []string
	for progress := true; progress; {
		progress = false
		for _, env := range chain {
			var e KeyEndorsement
			if err := t.Verify(env, TypeKeyEndorsement, &e); err != nil {
				continue // signer not trusted (yet) or invalid
			}
			raw, err := base64.StdEncoding.DecodeString(e.PublicKey)
			if err != nil || len(raw) != ed25519.PublicKeySize {
				continue
			}
			pub := ed25519.PublicKey(raw)
			if KeyID(pub) != e.KeyID {
				continue
			}
			if _, ok := t[e.KeyID]; ok {
				continue
			}
			t[e.KeyID] = pub
			added = append(added, e.KeyID)
			progress = true
		}
	}
	return added
}

// Clone copies the key set.
func (t TrustedKeys) Clone() TrustedKeys {
	out := make(TrustedKeys, len(t))
	for k, v := range t {
		out[k] = v
	}
	return out
}

// PEMBlockEndorsement armours a key endorsement inside a license bundle.
const PEMBlockEndorsement = "MYDNS KEY ENDORSEMENT"

// EncodeBundle renders a license file followed by the key endorsements a
// server needs to verify it (used for offline activation).
func EncodeBundle(license *Envelope, chain []*Envelope) (string, error) {
	text, err := EncodeArmored(license, PEMBlockLicense)
	if err != nil {
		return "", err
	}
	for _, e := range chain {
		t, err := EncodeArmored(e, PEMBlockEndorsement)
		if err != nil {
			return "", err
		}
		text += t
	}
	return text, nil
}

// DecodeBundle parses a license file and any endorsements that follow it.
func DecodeBundle(text string) (*Envelope, []*Envelope, error) {
	var license *Envelope
	var chain []*Envelope
	rest := []byte(text)
	for {
		block, r := pem.Decode(rest)
		if block == nil {
			break
		}
		rest = r
		env, err := decodeEnvelopeJSON(block.Bytes)
		if err != nil {
			return nil, nil, err
		}
		switch block.Type {
		case PEMBlockLicense:
			if license != nil {
				return nil, nil, fmt.Errorf("%w: more than one license in file", ErrMalformed)
			}
			license = env
		case PEMBlockEndorsement:
			chain = append(chain, env)
		}
	}
	if license == nil {
		// Also accept a bare JSON envelope.
		env, err := DecodeArmored(text, PEMBlockLicense)
		if err != nil {
			return nil, nil, err
		}
		license = env
	}
	return license, chain, nil
}
