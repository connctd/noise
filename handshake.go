package noise

import "errors"

// Identity is an interface which provides the public key of a static identity to the HandshakeState
type Identity interface {
	PublicKey() []byte
}

// PrivateIdentity is an Identity with access to the private key
type PrivateIdentity interface {
	Identity
	PrivateKey() []byte
}

// ReadableHandshakeMessage provides the HandshakeState the possibility to digest handshake messages in other
// formats than simple concatenated byte slices
type ReadableHandshakeMessage interface {
	ReadEPublic() ([]byte, error)
	ReadEncryptedIdentity() ([]byte, error)
	ReadPayload() []byte
	Length() int
}

// WriteableHandshakeMessage takes data from the HandshakeState to marshal it to a custom format.
type WriteableHandshakeMessage interface {
	WriteEPublic(e []byte)
	WriteEncryptedIdentity(s []byte)
	WriteEncryptedPayload(p []byte)
}

// SimplePayload is mostly used for testing, but can also be used to emulate the previous behavior
// of simply concatenating bytes together
type SimplePayload struct {
	epublic           []byte
	encryptedIdentity []byte
	payload           []byte
}

// Reset sets the fields to empty values, used in testing
func (s *SimplePayload) Reset() {
	s.encryptedIdentity = []byte{}
	s.epublic = []byte{}
	s.payload = []byte{}
}

// WriteEPublic writes the ephemeral public key to the payload
func (s *SimplePayload) WriteEPublic(e []byte) {
	s.epublic = make([]byte, len(e))
	copy(s.epublic, e)
}

// WriteEncryptedIdentity writes the encrypted static identity (public key) to this payload
func (s *SimplePayload) WriteEncryptedIdentity(sr []byte) {
	s.encryptedIdentity = make([]byte, len(sr))
	copy(s.encryptedIdentity, sr)
}

// WriteEncryptedPayload adds the encrypted payload
func (s *SimplePayload) WriteEncryptedPayload(p []byte) {
	s.payload = make([]byte, len(p))
	copy(s.payload, p)
}

// ReadEPublic gives you the ephemeral remote public key from this payload
func (s *SimplePayload) ReadEPublic() ([]byte, error) {
	return s.epublic, nil
}

// ReadEncryptedIdentity gives you the bytes of the encrypted static remote identity (key)
func (s *SimplePayload) ReadEncryptedIdentity() ([]byte, error) {
	return s.encryptedIdentity, nil
}

// ReadPayload gives you the encrypted bytes of the additional optional payload
func (s *SimplePayload) ReadPayload() []byte {
	return s.payload
}

// Serialize simply concatenates all fields in an expected order
func (s *SimplePayload) Serialize() []byte {
	t := append(s.epublic, s.encryptedIdentity...)
	return append(t, s.payload...)
}

// Length gives you the total length of this message
func (s *SimplePayload) Length() int {
	return len(s.Serialize())
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
