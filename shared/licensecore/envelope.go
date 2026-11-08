// Package licensecore holds the signed-document format shared by the
// License Manager (which signs) and ISP NetControl (which verifies).
//
// A signed document is an Envelope: a JSON payload, the ID of the Ed25519 key
// that signed it, a document type, and the signature. The signature covers a
// domain-separated string built from the type, the key ID and the exact
// base64url payload bytes, so a payload cannot be re-encoded, a status
// document cannot be passed off as a license, and the key ID cannot be swapped.
package licensecore

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
)

const (
	EnvelopeVersion = 1

	TypeLicense = "license"
	TypeStatus  = "status"

	// PEMBlockLicense is the armour used for license files that are copied
	// by hand (offline activation).
	PEMBlockLicense = "ISP NETCONTROL LICENSE"
	// PEMBlockPublicKey is the armour for a trusted signing key.
	PEMBlockPublicKey = "MYDNS LICENSE SIGNING KEY"

	signingDomain = "MYDNS-ENVELOPE-v1"
)

var (
	ErrMalformed    = errors.New("malformed signed document")
	ErrUnknownKey   = errors.New("signed by a key that is not trusted")
	ErrBadSignature = errors.New("signature does not verify")
	ErrWrongType    = errors.New("signed document has the wrong type")
)

// Envelope is the wire form of a signed document.
type Envelope struct {
	Version   int    `json:"v"`
	Type      string `json:"typ"`
	KeyID     string `json:"kid"`
	Payload   string `json:"payload"` // base64url (no padding) of the JSON payload
	Signature string `json:"sig"`     // base64url (no padding) Ed25519 signature
}

var b64 = base64.RawURLEncoding

// KeyID derives the stable identifier of a public key.
func KeyID(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:8])
}

func signingInput(typ, kid, payload string) []byte {
	var buf bytes.Buffer
	buf.WriteString(signingDomain)
	buf.WriteByte(0)
	buf.WriteString(typ)
	buf.WriteByte(0)
	buf.WriteString(kid)
	buf.WriteByte(0)
	buf.WriteString(payload)
	return buf.Bytes()
}

// Sign marshals v to JSON and signs it with priv.
func Sign(priv ed25519.PrivateKey, typ string, v any) (*Envelope, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return nil, errors.New("invalid Ed25519 private key")
	}
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	pub := priv.Public().(ed25519.PublicKey)
	env := &Envelope{
		Version: EnvelopeVersion,
		Type:    typ,
		KeyID:   KeyID(pub),
		Payload: b64.EncodeToString(raw),
	}
	env.Signature = b64.EncodeToString(ed25519.Sign(priv, signingInput(env.Type, env.KeyID, env.Payload)))
	return env, nil
}

// TrustedKeys maps key IDs to public keys.
type TrustedKeys map[string]ed25519.PublicKey

// Add trusts pub under its derived key ID.
func (t TrustedKeys) Add(pub ed25519.PublicKey) string {
	kid := KeyID(pub)
	t[kid] = pub
	return kid
}

// Verify checks the envelope against the trusted keys and, on success,
// unmarshals the payload into out. The payload is never decoded before the
// signature has been checked.
func (t TrustedKeys) Verify(env *Envelope, typ string, out any) error {
	if env == nil || env.Version != EnvelopeVersion || env.KeyID == "" || env.Payload == "" || env.Signature == "" {
		return ErrMalformed
	}
	if env.Type != typ {
		return ErrWrongType
	}
	pub, ok := t[env.KeyID]
	if !ok {
		return ErrUnknownKey
	}
	sig, err := b64.DecodeString(env.Signature)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return ErrMalformed
	}
	if !ed25519.Verify(pub, signingInput(env.Type, env.KeyID, env.Payload), sig) {
		return ErrBadSignature
	}
	raw, err := b64.DecodeString(env.Payload)
	if err != nil {
		return ErrMalformed
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(out); err != nil {
		return fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	return nil
}

// EncodeArmored renders an envelope as a PEM-style text block that survives
// copy and paste (used for offline license files).
func EncodeArmored(env *Envelope, blockType string) (string, error) {
	raw, err := json.Marshal(env)
	if err != nil {
		return "", err
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: raw})), nil
}

// DecodeArmored parses either an armoured block or a bare JSON envelope.
func DecodeArmored(text string, blockType string) (*Envelope, error) {
	data := []byte(strings.TrimSpace(text))
	if bytes.HasPrefix(data, []byte("-----BEGIN")) {
		block, _ := pem.Decode(data)
		if block == nil || block.Type != blockType {
			return nil, ErrMalformed
		}
		data = block.Bytes
	}
	return decodeEnvelopeJSON(data)
}

func decodeEnvelopeJSON(data []byte) (*Envelope, error) {
	var env Envelope
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&env); err != nil {
		return nil, ErrMalformed
	}
	return &env, nil
}

// EncodePublicKey renders a public key in PEM armour.
func EncodePublicKey(pub ed25519.PublicKey) string {
	return string(pem.EncodeToMemory(&pem.Block{
		Type:    PEMBlockPublicKey,
		Headers: map[string]string{"Key-ID": KeyID(pub)},
		Bytes:   pub,
	}))
}

// ParsePublicKeys parses every signing-key block in text.
func ParsePublicKeys(text string) (TrustedKeys, error) {
	keys := TrustedKeys{}
	rest := []byte(text)
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != PEMBlockPublicKey {
			continue
		}
		if len(block.Bytes) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("signing key block has wrong length %d", len(block.Bytes))
		}
		pub := ed25519.PublicKey(block.Bytes)
		kid := keys.Add(pub)
		if want, ok := block.Headers["Key-ID"]; ok && want != kid {
			return nil, fmt.Errorf("signing key header Key-ID %s does not match key (%s)", want, kid)
		}
	}
	return keys, nil
}
