package noise

type ReadableHandshakeMessage interface {
	ReadEPublic() ([]byte, error)
	ReadEncryptedSPublic() ([]byte, error)
	ReadPayload() []byte
	Length() int
}

type WriteableHandshakeMessage interface {
	WriteEPublic(e []byte)
	WriteEncryptedSPublic(s []byte)
	WriteEncryptedPayload(p []byte)
}

type SimplePayload struct {
	epublic  []byte
	espublic []byte
	payload  []byte
}

func (s *SimplePayload) Reset() {
	s.espublic = []byte{}
	s.epublic = []byte{}
	s.payload = []byte{}
}

func (s *SimplePayload) WriteEPublic(e []byte) {
	s.epublic = e
}

func (p *SimplePayload) WriteEncryptedSPublic(s []byte) {
	p.espublic = s
}

func (s *SimplePayload) WriteEncryptedPayload(p []byte) {
	s.payload = p
}

func (s *SimplePayload) ReadEPublic() ([]byte, error) {
	return s.epublic, nil
}

func (s *SimplePayload) ReadEncryptedSPublic() ([]byte, error) {
	return s.espublic, nil
}

func (s *SimplePayload) ReadPayload() []byte {
	return s.payload
}

func (s *SimplePayload) Serialize() []byte {
	t := append(s.epublic, s.espublic...)
	return append(t, s.payload...)
}

func (s *SimplePayload) Length() int {
	return len(s.Serialize())
}
