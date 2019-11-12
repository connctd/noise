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
