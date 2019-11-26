package noise

type Identity interface {
	PublicKey() []byte
	Bytes() []byte
}

type PrivateIdentity interface {
	Identity
	PrivateKey() []byte
}

type ReadableHandshakeMessage interface {
	ReadEPublic() ([]byte, error)
	ReadEncryptedIdentity() ([]byte, error)
	SetUnmarshalledIdentity(identity Identity)
	ReadPayload() []byte
	Length() int
}

type WriteableHandshakeMessage interface {
	WriteEPublic(e []byte)
	WriteEncryptedIdentity(s []byte)
	WriteEncryptedPayload(p []byte)
}

type SimplePayload struct {
	epublic           []byte
	encryptedIdentity []byte
	payload           []byte

	identity Identity
}

func (s *SimplePayload) Reset() {
	s.encryptedIdentity = []byte{}
	s.epublic = []byte{}
	s.payload = []byte{}
}

func (s *SimplePayload) WriteEPublic(e []byte) {
	s.epublic = e
}

func (p *SimplePayload) WriteEncryptedIdentity(s []byte) {
	p.encryptedIdentity = s
}

func (s *SimplePayload) WriteEncryptedPayload(p []byte) {
	s.payload = p
}

func (s *SimplePayload) ReadEPublic() ([]byte, error) {
	return s.epublic, nil
}

func (s *SimplePayload) ReadEncryptedIdentity() ([]byte, error) {
	return s.encryptedIdentity, nil
}

func (s *SimplePayload) SetUnmarshalledIdentity(identity Identity) {
	s.identity = identity
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

func (d DHKey) Bytes() []byte {
	return d.Public
}
