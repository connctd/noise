package noise

import (
	"bytes"
	"fmt"

	"github.com/iost-official/ed25519/extra25519"
	"github.com/smolcert/smolcert"
	"golang.org/x/crypto/ed25519"
)

// SmolIdentity wraps a smolcert based certificate and provides the public
// key as curve25519 representation instead of ed25519
type SmolIdentity struct {
	smolcert.Certificate
}

// PublicKey returns the curve25519 representation of the ed25519 public key of this certificate
func (s *SmolIdentity) PublicKey() []byte {
	// The certificates used by Smolcert use ed25519 keys, but we need curve25519 keys.
	// As they both are based on the same curve, we can convert them.
	var curvePubKey [32]byte
	var edPubKey [32]byte
	copy(edPubKey[:], s.Certificate.PubKey)
	if !extra25519.PublicKeyToCurve25519(&curvePubKey, &edPubKey) {
		// Signal that we couldn't create a valid curve25519 representation
		return nil
	}
	return curvePubKey[:]
}

// Cert returns the plain smolcert certificate
func (s *SmolIdentity) Cert() *smolcert.Certificate {
	return &s.Certificate
}

// PrivateSmolIdentity wraps a SmolIdentity and an ed25519 private key
type PrivateSmolIdentity struct {
	SmolIdentity
	privKey ed25519.PrivateKey
}

// NewPrivateSmolIdentity creates a new PrivateSmolIdentity which contains the smolcert with the private key.
// This might be needed for cryptographic operations like eDH or eDSA etc.
func NewPrivateSmolIdentity(cert *smolcert.Certificate, privKey ed25519.PrivateKey) *PrivateSmolIdentity {
	return &PrivateSmolIdentity{
		SmolIdentity: SmolIdentity{
			Certificate: *cert,
		},
		privKey: privKey,
	}
}

// PrivateKey returns a curve25519 representation of the private key
func (p *PrivateSmolIdentity) PrivateKey() []byte {
	var edPrivKey [64]byte
	var curvePrivKey [32]byte
	copy(edPrivKey[:], p.privKey)
	extra25519.PrivateKeyToCurve25519(&curvePrivKey, &edPrivKey)
	return curvePrivKey[:]
}

// SmolIdentityVerifier verifies certificates against a set of root certificates
type SmolIdentityVerifier struct {
	pool *smolcert.CertPool
}

func NewSmolIdentityVerifier(rootCerts ...*smolcert.Certificate) *SmolIdentityVerifier {
	return &SmolIdentityVerifier{
		pool: smolcert.NewCertPool(rootCerts...),
	}
}

func (s *SmolIdentityVerifier) VerifyIdentity(id Identity) error {
	if smolID, ok := id.(*SmolIdentity); ok {
		return s.pool.Validate(smolID.Cert())
	}
	return fmt.Errorf("Invalid identity type: %T", id)
}

type SmolIdentityMarshaler struct{}

func (s SmolIdentityMarshaler) UnmarshalIdentity(identityBytes []byte) (Identity, error) {
	cert, err := smolcert.Parse(bytes.NewBuffer(identityBytes))
	return &SmolIdentity{*cert}, err
}

func (s SmolIdentityMarshaler) MarshalIdentity(identity Identity) ([]byte, error) {
	switch smolID := identity.(type) {
	case *smolcert.Certificate:
		return smolID.Bytes()
	case *SmolIdentity:
		return smolID.Bytes()
	case *PrivateSmolIdentity:
		return smolID.Bytes()
	default:
		return nil, fmt.Errorf("Invalid identity type: %T", smolID)
	}
}

func NewSmolHandshakeState(c Config, rootCerts ...*smolcert.Certificate) (*HandshakeState, error) {
	c.IDMarshaler = &SmolIdentityMarshaler{}
	c.IDVerifier = NewSmolIdentityVerifier(rootCerts...)
	c.CipherSuite = NewCipherSuite(DH25519, CipherChaChaPoly, HashBLAKE2s)
	return NewHandshakeState(c)
}
