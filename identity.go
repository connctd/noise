package noise

import "errors"

// Identity is an interface which provides the public key of a static identity to the HandshakeState
type Identity interface {
	PublicKey() []byte
}

// IdentityMarshaler provides the HandshakeState with the ability to marshal und unmarshal identities
// from byte slices, enabling the use of certificates instead of plain public keys
type IdentityMarshaler interface {
	UnmarshalIdentity(identityBytes []byte) (Identity, error)

	MarshalIdentity(identity Identity) ([]byte, error)
}

// PrivateIdentity is an Identity with access to the private key
type PrivateIdentity interface {
	Identity
	PrivateKey() []byte
}

// IdentityVerifier can be used by a HandshakeState to verify the remote identity fulfills certain
// criteria (i.e. signed by common authority etc.)
type IdentityVerifier interface {
	VerifyIdentity(id Identity) error
}

// SimpleIdentity gives the possibility to simply use plain public keys as identity,
// similar to the original behavior
type SimpleIdentity struct {
	// PubKey is the static public key
	PubKey []byte
}

// PublicKey gives you the static public key of this identity
func (s *SimpleIdentity) PublicKey() []byte {
	return s.PubKey
}

// PublicKey gives you the static public key of DHKey which is used as PrivateIdentity here
func (d DHKey) PublicKey() []byte {
	return d.Public
}

// PrivateKey returns the private key part of DHKey
func (d DHKey) PrivateKey() []byte {
	return d.Private
}

type simpleIdentityMarshaler struct{}

func (s simpleIdentityMarshaler) MarshalIdentity(identity Identity) ([]byte, error) {
	if len(identity.PublicKey()) == 0 {
		return nil, errors.New("Invalid identity with public key length of 0")
	}
	rawID := make([]byte, len(identity.PublicKey()))
	copy(rawID, identity.PublicKey())
	return rawID, nil
}

func (s simpleIdentityMarshaler) UnmarshalIdentity(identityBytes []byte) (Identity, error) {
	simpleID := &SimpleIdentity{
		PubKey: make([]byte, len(identityBytes)),
	}
	copy(simpleID.PubKey, identityBytes)
	return simpleID, nil
}
