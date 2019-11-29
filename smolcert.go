// +build smolcert

package noise

import (
	"bytes"
	"fmt"
	"github.com/connctd/smolcert"
	"golang.org/x/crypto/ed25519"
)

type PrivateSmolIdentity struct {
	smolcert.Certificate
	privKey ed25519.PrivateKey
}

func (p *PrivateSmolIdentity) PrivateKey() []byte {
	return p.privKey
}

type SmolIdentityVerifier struct {
	pool *smolcert.CertPool
}

func NewSmolIdentityVerifier(rootCerts ...*smolcert.Certificate) *SmolIdentityVerifier {
	return &SmolIdentityVerifier{
		pool: smolcert.NewCertPool(rootCerts...),
	}
}

func (s *SmolIdentityVerifier) VerifyIdentity(id Identity) error {
	if smolID, ok := id.(*smolcert.Certificate); ok {
		return s.pool.Validate(smolID)
	}
	return fmt.Errorf("Invalid identity type: %T", id)
}

type SmolIdentityMarshaler struct{}

func (s SmolIdentityMarshaler) UnmarshalIdentity(identityBytes []byte) (Identity, error) {
	return smolcert.Parse(bytes.NewBuffer(identityBytes))
}

func (s SmolIdentityMarshaler) MarshalIdentity(identity Identity) ([]byte, error) {
	if smolID, ok := identity.(*smolcert.Certificate); ok {
		return smolID.Bytes()
	}
	return nil, fmt.Errorf("Invalid identity type: %T", identity)
}
