package noise

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

// SimpleMessage is mostly used for testing, but can also be used to emulate the previous behavior
// of simply concatenating bytes together
type SimpleMessage struct {
	epublic           []byte
	encryptedIdentity []byte
	payload           []byte
}

// Reset sets the fields to empty values, used in testing
func (s *SimpleMessage) Reset() {
	s.encryptedIdentity = []byte{}
	s.epublic = []byte{}
	s.payload = []byte{}
}

// WriteEPublic writes the ephemeral public key to the payload
func (s *SimpleMessage) WriteEPublic(e []byte) {
	s.epublic = make([]byte, len(e))
	copy(s.epublic, e)
}

// WriteEncryptedIdentity writes the encrypted static identity (public key) to this payload
func (s *SimpleMessage) WriteEncryptedIdentity(sr []byte) {
	s.encryptedIdentity = make([]byte, len(sr))
	copy(s.encryptedIdentity, sr)
}

// WriteEncryptedPayload adds the encrypted payload
func (s *SimpleMessage) WriteEncryptedPayload(p []byte) {
	s.payload = make([]byte, len(p))
	copy(s.payload, p)
}

// ReadEPublic gives you the ephemeral remote public key from this payload
func (s *SimpleMessage) ReadEPublic() ([]byte, error) {
	return s.epublic, nil
}

// ReadEncryptedIdentity gives you the bytes of the encrypted static remote identity (key)
func (s *SimpleMessage) ReadEncryptedIdentity() ([]byte, error) {
	return s.encryptedIdentity, nil
}

// ReadPayload gives you the encrypted bytes of the additional optional payload
func (s *SimpleMessage) ReadPayload() []byte {
	return s.payload
}

// Serialize simply concatenates all fields in an expected order
func (s *SimpleMessage) Serialize() []byte {
	t := append(s.epublic, s.encryptedIdentity...)
	return append(t, s.payload...)
}

// Length gives you the total length of this message
func (s *SimpleMessage) Length() int {
	return len(s.Serialize())
}
