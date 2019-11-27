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

type SimplePayload struct {
	epublic           []byte
	encryptedIdentity []byte
	payload           []byte
}

func (s *SimplePayload) Reset() {
	s.encryptedIdentity = []byte{}
	s.epublic = []byte{}
	s.payload = []byte{}
}

func (s *SimplePayload) WriteEPublic(e []byte) {
	s.epublic = make([]byte, len(e))
	copy(s.epublic, e)
}

func (s *SimplePayload) WriteEncryptedIdentity(sr []byte) {
	s.encryptedIdentity = make([]byte, len(sr))
	copy(s.encryptedIdentity, sr)
}

func (s *SimplePayload) WriteEncryptedPayload(p []byte) {
	s.payload = make([]byte, len(p))
	copy(s.payload, p)
}

func (s *SimplePayload) ReadEPublic() ([]byte, error) {
	return s.epublic, nil
}

func (s *SimplePayload) ReadEncryptedIdentity() ([]byte, error) {
	return s.encryptedIdentity, nil
}

func (s *SimplePayload) ReadPayload() []byte {
	return s.payload
}

func (s *SimplePayload) Serialize() []byte {
	t := append(s.epublic, s.encryptedIdentity...)
	return append(t, s.payload...)
}

func (s *SimplePayload) Length() int {
	return len(s.Serialize())
}

type SimpleIdentity struct {
	PubKey []byte
}

func (s *SimpleIdentity) PublicKey() []byte {
	return s.PubKey
}

func (d DHKey) PublicKey() []byte {
	return d.Public
}

func (d DHKey) PrivateKey() []byte {
	return d.Private
}

type simpleIdentityMarshaller struct{}

func (s simpleIdentityMarshaller) MarshallIdentity(identity Identity) ([]byte, error) {
	if len(identity.PublicKey()) == 0 {
		return nil, errors.New("Invalid identity with public key length of 0")
	}
	rawID := make([]byte, len(identity.PublicKey()))
	copy(rawID, identity.PublicKey())
	return rawID, nil
}

func (s simpleIdentityMarshaller) UnmarshallIdentity(identityBytes []byte) (Identity, error) {
	simpleID := &SimpleIdentity{
		PubKey: make([]byte, len(identityBytes)),
	}
	copy(simpleID.PubKey, identityBytes)
	return simpleID, nil
}
