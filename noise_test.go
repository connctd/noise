package noise

import (
	"encoding/hex"
	"testing"

	. "gopkg.in/check.v1"
)

func Test(t *testing.T) { TestingT(t) }

type NoiseSuite struct{}

var _ = Suite(&NoiseSuite{})

type RandomInc byte

func (r *RandomInc) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = byte(*r)
		*r = (*r) + 1
	}
	return len(p), nil
}

func (NoiseSuite) TestN(c *C) {
	cs := NewCipherSuite(DH25519, CipherAESGCM, HashSHA256)
	rng := new(RandomInc)
	staticR, _ := cs.GenerateKeypair(rng)
	hs, _ := NewHandshakeState(Config{
		CipherSuite: cs,
		Random:      rng,
		Pattern:     HandshakeN,
		Initiator:   true,
		PeerStatic:  staticR.Public,
	})

	out := &SimplePayload{}

	hs.WriteMessage(out, nil)
	expected, _ := hex.DecodeString("358072d6365880d1aeea329adf9121383851ed21a28e3b75e965d0d2cd1662548331a3d1e93b490263abc7a4633867f4")
	c.Assert(out.Serialize(), DeepEquals, expected)
}

func (NoiseSuite) TestX(c *C) {
	cs := NewCipherSuite(DH25519, CipherChaChaPoly, HashSHA256)
	rng := new(RandomInc)
	staticI, _ := cs.GenerateKeypair(rng)
	staticR, _ := cs.GenerateKeypair(rng)
	hs, _ := NewHandshakeState(Config{
		CipherSuite:   cs,
		Random:        rng,
		Pattern:       HandshakeX,
		Initiator:     true,
		StaticKeypair: staticI,
		PeerStatic:    staticR.Public,
	})

	out := &SimplePayload{}
	hs.WriteMessage(out, nil)
	expected, _ := hex.DecodeString("79a631eede1bf9c98f12032cdeadd0e7a079398fc786b88cc846ec89af85a51ad203cd28d81cf65a2da637f557a05728b3ae4abdc3a42d1cda5f719d6cf41d7f2cf1b1c5af10e38a09a9bb7e3b1d589a99492cc50293eaa1f3f391b59bb6990d")
	c.Assert(out.Serialize(), DeepEquals, expected)
}

func (NoiseSuite) TestNN(c *C) {
	cs := NewCipherSuite(DH25519, CipherAESGCM, HashSHA512)
	rngI := new(RandomInc)
	rngR := new(RandomInc)
	*rngR = 1

	hsI, _ := NewHandshakeState(Config{
		CipherSuite: cs,
		Random:      rngI,
		Pattern:     HandshakeNN,
		Initiator:   true,
	})
	hsR, _ := NewHandshakeState(Config{
		CipherSuite: cs,
		Random:      rngR,
		Pattern:     HandshakeNN,
		Initiator:   false,
	})

	in := &SimplePayload{}
	hsI.WriteMessage(in, []byte("abc"))
	c.Assert(in.Serialize(), HasLen, 35)
	var res []byte
	res, _, _, err := hsR.ReadMessage(res, in)
	c.Assert(err, IsNil)
	c.Assert(string(res), Equals, "abc")

	in.Reset()
	hsR.WriteMessage(in, []byte("defg"))
	c.Assert(in.Serialize(), HasLen, 52)
	res, _, _, err = hsI.ReadMessage(nil, in)
	c.Assert(err, IsNil)
	c.Assert(string(res), Equals, "defg")

	expected, _ := hex.DecodeString("07a37cbc142093c8b755dc1b10e86cb426374ad16aa853ed0bdfc0b2b86d1c7c5e4dc9545d41b3280f4586a5481829e1e24ec5a0")
	c.Assert(in.Serialize(), DeepEquals, expected)
}

func (NoiseSuite) TestXX(c *C) {
	cs := NewCipherSuite(DH25519, CipherAESGCM, HashSHA256)
	rngI := new(RandomInc)
	rngR := new(RandomInc)
	*rngR = 1

	staticI, _ := cs.GenerateKeypair(rngI)
	staticR, _ := cs.GenerateKeypair(rngR)

	hsI, _ := NewHandshakeState(Config{
		CipherSuite:   cs,
		Random:        rngI,
		Pattern:       HandshakeXX,
		Initiator:     true,
		StaticKeypair: staticI,
	})
	hsR, _ := NewHandshakeState(Config{
		CipherSuite:   cs,
		Random:        rngR,
		Pattern:       HandshakeXX,
		StaticKeypair: staticR,
	})
	out := &SimplePayload{}
	hsI.WriteMessage(out, []byte("abc"))
	c.Assert(out.Serialize(), HasLen, 35)
	var payload []byte
	payload, _, _, err := hsR.ReadMessage(payload, out)
	c.Assert(err, IsNil)
	c.Assert(string(payload), Equals, "abc")

	hsR.WriteMessage(out, []byte("defg"))
	c.Assert(out.Serialize(), HasLen, 100)
	payload, _, _, err = hsI.ReadMessage(nil, out)
	c.Assert(err, IsNil)
	c.Assert(string(payload), Equals, "defg")

	out.Reset()
	hsI.WriteMessage(out, nil)
	c.Assert(out.Serialize(), HasLen, 64)
	payload, _, _, err = hsR.ReadMessage(nil, out)
	c.Assert(err, IsNil)
	c.Assert(payload, HasLen, 0)

	expected, _ := hex.DecodeString("8127f4b35cdbdf0935fcf1ec99016d1dcbc350055b8af360be196905dfb50a2c1c38a7ca9cb0cfe8f4576f36c47a4933eee32288f590ac4305d4b53187577be7")
	c.Assert(out.Serialize(), DeepEquals, expected)
}

func (NoiseSuite) TestIK(c *C) {
	cs := NewCipherSuite(DH25519, CipherAESGCM, HashSHA256)
	rngI := new(RandomInc)
	rngR := new(RandomInc)
	*rngR = 1

	staticI, _ := cs.GenerateKeypair(rngI)
	staticR, _ := cs.GenerateKeypair(rngR)

	hsI, _ := NewHandshakeState(Config{
		CipherSuite:   cs,
		Random:        rngI,
		Pattern:       HandshakeIK,
		Initiator:     true,
		Prologue:      []byte("ABC"),
		StaticKeypair: staticI,
		PeerStatic:    staticR.Public,
	})
	hsR, _ := NewHandshakeState(Config{
		CipherSuite:   cs,
		Random:        rngR,
		Pattern:       HandshakeIK,
		Prologue:      []byte("ABC"),
		StaticKeypair: staticR,
	})

	out := &SimplePayload{}
	hsI.WriteMessage(out, []byte("abc"))
	c.Assert(out.Serialize(), HasLen, 99)
	var payload []byte
	payload, _, _, err := hsR.ReadMessage(payload, out)
	c.Assert(err, IsNil)
	c.Assert(string(payload), Equals, "abc")

	out.Reset()
	hsR.WriteMessage(out, []byte("defg"))
	c.Assert(out.Serialize(), HasLen, 52)
	payload, _, _, err = hsI.ReadMessage(nil, out)
	c.Assert(err, IsNil)
	c.Assert(string(payload), Equals, "defg")

	expected, _ := hex.DecodeString("5869aff450549732cbaaed5e5df9b30a6da31cb0e5742bad5ad4a1a768f1a67b7555a94199d0ce2972e0861b06c2152419a278de")
	c.Assert(out.Serialize(), DeepEquals, expected)
}

func (NoiseSuite) TestXXRoundtrip(c *C) {
	cs := NewCipherSuite(DH25519, CipherAESGCM, HashSHA256)
	rngI := new(RandomInc)
	rngR := new(RandomInc)
	*rngR = 1

	staticI, _ := cs.GenerateKeypair(rngI)
	staticR, _ := cs.GenerateKeypair(rngR)

	hsI, _ := NewHandshakeState(Config{
		CipherSuite:   cs,
		Random:        rngI,
		Pattern:       HandshakeXX,
		Initiator:     true,
		StaticKeypair: staticI,
	})
	hsR, _ := NewHandshakeState(Config{
		CipherSuite:   cs,
		Random:        rngR,
		Pattern:       HandshakeXX,
		StaticKeypair: staticR,
	})

	// -> e
	out := &SimplePayload{}
	hsI.WriteMessage(out, []byte("abcdef"))
	c.Assert(out.Serialize(), HasLen, 38)
	var payload []byte
	payload, _, _, err := hsR.ReadMessage(payload, out)
	c.Assert(err, IsNil)
	c.Assert(string(payload), Equals, "abcdef")

	out.Reset()
	// <- e, dhee, s, dhse
	hsR.WriteMessage(out, nil)
	c.Assert(out.Serialize(), HasLen, 96)
	payload, _, _, err = hsI.ReadMessage(nil, out)
	c.Assert(err, IsNil)
	c.Assert(payload, HasLen, 0)

	// -> s, dhse
	out.Reset()
	expectedPayload := []byte("0123456789012345678901234567890123456789012345678901234567890123456789")
	csI0, csI1, _ := hsI.WriteMessage(out, expectedPayload)
	c.Assert(out.Serialize(), HasLen, 134)
	payload, csR0, csR1, err := hsR.ReadMessage(nil, out)
	c.Assert(err, IsNil)
	c.Assert(string(expectedPayload), Equals, string(payload))

	// transport message I -> R
	msg := csI0.Encrypt(nil, nil, []byte("wubba"))
	res, err := csR0.Decrypt(nil, nil, msg)
	c.Assert(err, IsNil)
	c.Assert(string(res), Equals, "wubba")

	// transport message I -> R again
	msg = csI0.Encrypt(nil, nil, []byte("aleph"))
	res, err = csR0.Decrypt(nil, nil, msg)
	c.Assert(err, IsNil)
	c.Assert(string(res), Equals, "aleph")

	// transport message R <- I
	msg = csR1.Encrypt(nil, nil, []byte("worri"))
	res, err = csI1.Decrypt(nil, nil, msg)
	c.Assert(err, IsNil)
	c.Assert(string(res), Equals, "worri")
}

func (NoiseSuite) Test_NNpsk0_Roundtrip(c *C) {
	cs := NewCipherSuite(DH25519, CipherChaChaPoly, HashBLAKE2b)
	rngI := new(RandomInc)
	rngR := new(RandomInc)
	*rngR = 1

	hsI, _ := NewHandshakeState(Config{
		CipherSuite:  cs,
		Random:       rngI,
		Pattern:      HandshakeNN,
		Initiator:    true,
		PresharedKey: []byte("supersecretsupersecretsupersecre"),
	})
	hsR, _ := NewHandshakeState(Config{
		CipherSuite:  cs,
		Random:       rngR,
		Pattern:      HandshakeNN,
		PresharedKey: []byte("supersecretsupersecretsupersecre"),
	})

	// -> e
	out := &SimplePayload{}
	hsI.WriteMessage(out, nil)
	c.Assert(out.Serialize(), HasLen, 48)
	res, _, _, err := hsR.ReadMessage(nil, out)
	c.Assert(err, IsNil)
	c.Assert(res, HasLen, 0)

	// <- e, dhee
	csR0, csR1, _ := hsR.WriteMessage(out, nil)
	c.Assert(out.Serialize(), HasLen, 48)
	res, csI0, csI1, err := hsI.ReadMessage(nil, out)
	c.Assert(err, IsNil)
	c.Assert(res, HasLen, 0)

	// transport I -> R
	msg := csI0.Encrypt(nil, nil, []byte("foo"))
	res, err = csR0.Decrypt(nil, nil, msg)
	c.Assert(err, IsNil)
	c.Assert(string(res), Equals, "foo")

	// transport R -> I
	msg = csR1.Encrypt(nil, nil, []byte("bar"))
	res, err = csI1.Decrypt(nil, nil, msg)
	c.Assert(err, IsNil)
	c.Assert(string(res), Equals, "bar")
}

func (NoiseSuite) Test_Npsk0(c *C) {
	cs := NewCipherSuite(DH25519, CipherAESGCM, HashSHA256)
	rng := new(RandomInc)
	staticR, _ := cs.GenerateKeypair(rng)

	hsI, _ := NewHandshakeState(Config{
		CipherSuite:  cs,
		Random:       rng,
		Pattern:      HandshakeN,
		Initiator:    true,
		PresharedKey: []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20},
		PeerStatic:   staticR.Public,
	})
	out := &SimplePayload{}
	hsI.WriteMessage(out, nil)
	c.Assert(out.Serialize(), HasLen, 48)

	expected, _ := hex.DecodeString("358072d6365880d1aeea329adf9121383851ed21a28e3b75e965d0d2cd1662542044ae563929068930dcf04674526cb9")
	c.Assert(out.Serialize(), DeepEquals, expected)
}

func (NoiseSuite) Test_Xpsk0(c *C) {
	cs := NewCipherSuite(DH25519, CipherChaChaPoly, HashSHA256)
	rng := new(RandomInc)
	staticI, _ := cs.GenerateKeypair(rng)
	staticR, _ := cs.GenerateKeypair(rng)

	hs, _ := NewHandshakeState(Config{
		CipherSuite:   cs,
		Random:        rng,
		Pattern:       HandshakeX,
		Initiator:     true,
		PresharedKey:  []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20},
		StaticKeypair: staticI,
		PeerStatic:    staticR.Public,
	})
	out := &SimplePayload{}
	hs.WriteMessage(out, nil)
	c.Assert(out.Serialize(), HasLen, 96)

	expected, _ := hex.DecodeString("79a631eede1bf9c98f12032cdeadd0e7a079398fc786b88cc846ec89af85a51ad51eef529db0dd9127d4aa59a9183e118337d75a4e55e7e00f85c3d20ede536dd0112eec8c3b2a514018a90ab685b027dd24aa0c70b0c0f00524cc23785028b9")
	c.Assert(out.Serialize(), DeepEquals, expected)
}

func (NoiseSuite) Test_NNpsk0(c *C) {
	cs := NewCipherSuite(DH25519, CipherAESGCM, HashSHA512)
	rngI := new(RandomInc)
	rngR := new(RandomInc)
	*rngR = 1
	prologue := []byte{0x01, 0x02, 0x03}
	psk := []byte{0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23}

	hsI, _ := NewHandshakeState(Config{
		CipherSuite:  cs,
		Random:       rngI,
		Pattern:      HandshakeNN,
		Initiator:    true,
		Prologue:     prologue,
		PresharedKey: psk,
	})
	hsR, _ := NewHandshakeState(Config{
		CipherSuite:  cs,
		Random:       rngR,
		Pattern:      HandshakeNN,
		Prologue:     prologue,
		PresharedKey: psk,
	})

	out := &SimplePayload{}
	hsI.WriteMessage(out, []byte("abc"))
	c.Assert(out.Serialize(), HasLen, 51)
	res, _, _, err := hsR.ReadMessage(nil, out)
	c.Assert(err, IsNil)
	c.Assert(string(res), Equals, "abc")

	hsR.WriteMessage(out, []byte("defg"))
	c.Assert(out.Serialize(), HasLen, 52)
	res, _, _, err = hsI.ReadMessage(nil, out)
	c.Assert(err, IsNil)
	c.Assert(string(res), Equals, "defg")

	expected, _ := hex.DecodeString("07a37cbc142093c8b755dc1b10e86cb426374ad16aa853ed0bdfc0b2b86d1c7c3e42e140cfffbcdf5d9d2a1c24ce4cdbdf1eaf37")
	c.Assert(out.Serialize(), DeepEquals, expected)
}

func (NoiseSuite) Test_XXpsk0(c *C) {
	cs := NewCipherSuite(DH25519, CipherAESGCM, HashSHA256)
	rngI := new(RandomInc)
	rngR := new(RandomInc)
	*rngR = 1

	staticI, _ := cs.GenerateKeypair(rngI)
	staticR, _ := cs.GenerateKeypair(rngR)
	prologue := []byte{0x01, 0x02, 0x03}
	psk := []byte{0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23}

	hsI, _ := NewHandshakeState(Config{
		CipherSuite:   cs,
		Random:        rngI,
		Pattern:       HandshakeXX,
		Initiator:     true,
		Prologue:      prologue,
		PresharedKey:  psk,
		StaticKeypair: staticI,
	})
	hsR, _ := NewHandshakeState(Config{
		CipherSuite:   cs,
		Random:        rngR,
		Pattern:       HandshakeXX,
		Prologue:      prologue,
		PresharedKey:  psk,
		StaticKeypair: staticR,
	})

	out := &SimplePayload{}
	hsI.WriteMessage(out, []byte("abc"))
	c.Assert(out.Serialize(), HasLen, 51)
	res, _, _, err := hsR.ReadMessage(nil, out)
	c.Assert(err, IsNil)
	c.Assert(string(res), Equals, "abc")

	hsR.WriteMessage(out, []byte("defg"))
	c.Assert(out.Serialize(), HasLen, 100)
	res, _, _, err = hsI.ReadMessage(nil, out)
	c.Assert(err, IsNil)
	c.Assert(string(res), Equals, "defg")

	out.Reset()
	hsI.WriteMessage(out, nil)
	c.Assert(out.Serialize(), HasLen, 64)
	res, _, _, err = hsR.ReadMessage(nil, out)
	c.Assert(err, IsNil)
	c.Assert(res, HasLen, 0)

	expected, _ := hex.DecodeString("1b6d7cc3b13bd02217f9cdb98c50870db96281193dca4df570bf6230a603b686fd90d2914c7e797d9276ef8fb34b0c9d87faa048ce4bc7e7af21b6a450352275")
	c.Assert(out.Serialize(), DeepEquals, expected)
}

func (NoiseSuite) TestHandshakeRollback(c *C) {
	cs := NewCipherSuite(DH25519, CipherAESGCM, HashSHA512)
	rngI := new(RandomInc)
	rngR := new(RandomInc)
	*rngR = 1

	hsI, _ := NewHandshakeState(Config{
		CipherSuite: cs,
		Random:      rngI,
		Pattern:     HandshakeNN,
		Initiator:   true,
	})
	hsR, _ := NewHandshakeState(Config{
		CipherSuite: cs,
		Random:      rngR,
		Pattern:     HandshakeNN,
		Initiator:   false,
	})

	out := &SimplePayload{}
	hsI.WriteMessage(out, []byte("abc"))
	c.Assert(out.Serialize(), HasLen, 35)
	res, _, _, err := hsR.ReadMessage(nil, out)
	c.Assert(err, IsNil)
	c.Assert(string(res), Equals, "abc")

	hsR.WriteMessage(out, []byte("defg"))
	c.Assert(out.Serialize(), HasLen, 52)
	prev := out.epublic[1]
	out.epublic[1] = out.epublic[1] + 1
	_, _, _, err = hsI.ReadMessage(nil, out)
	c.Assert(err, Not(IsNil))
	out.epublic[1] = prev
	res, _, _, err = hsI.ReadMessage(nil, out)
	c.Assert(string(res), Equals, "defg")

	expected, _ := hex.DecodeString("07a37cbc142093c8b755dc1b10e86cb426374ad16aa853ed0bdfc0b2b86d1c7c5e4dc9545d41b3280f4586a5481829e1e24ec5a0")
	c.Assert(out.Serialize(), DeepEquals, expected)
}

func (NoiseSuite) TestRekey(c *C) {
	rng := new(RandomInc)

	clientStaticKeypair, _ := DH25519.GenerateKeypair(rng)
	clientConfig := Config{}
	clientConfig.CipherSuite = NewCipherSuite(DH25519, CipherChaChaPoly, HashBLAKE2b)
	clientConfig.Random = rng
	clientConfig.Pattern = HandshakeNN
	clientConfig.Initiator = true
	clientConfig.Prologue = []byte{0}
	clientConfig.StaticKeypair = clientStaticKeypair
	clientConfig.EphemeralKeypair, _ = DH25519.GenerateKeypair(rng)
	clientHs, _ := NewHandshakeState(clientConfig)

	serverStaticKeypair, _ := DH25519.GenerateKeypair(rng)
	serverConfig := Config{}
	serverConfig.CipherSuite = NewCipherSuite(DH25519, CipherChaChaPoly, HashBLAKE2b)
	serverConfig.Random = rng
	serverConfig.Pattern = HandshakeNN
	serverConfig.Initiator = false
	serverConfig.Prologue = []byte{0}
	serverConfig.StaticKeypair = serverStaticKeypair
	serverConfig.EphemeralKeypair, _ = DH25519.GenerateKeypair(rng)
	serverHs, _ := NewHandshakeState(serverConfig)

	out := &SimplePayload{}
	clientHs.WriteMessage(out, nil)
	c.Assert(32, Equals, out.Length())

	serverHsResult, _, _, err := serverHs.ReadMessage(nil, out)
	c.Assert(err, IsNil)
	c.Assert(0, Equals, len(serverHsResult))

	csR0, csR1, _ := serverHs.WriteMessage(out, nil)
	c.Assert(48, Equals, out.Length())

	clientHsResult, csI0, csI1, err := clientHs.ReadMessage(nil, out)
	c.Assert(err, IsNil)
	c.Assert(0, Equals, len(clientHsResult))

	clientMessage := []byte("hello")
	msg := csI0.Encrypt(nil, nil, clientMessage)
	res, err := csR0.Decrypt(nil, nil, msg)
	c.Assert(string(clientMessage), Equals, string(res))

	oldK := csI0.k
	csI0.Rekey()
	c.Assert(oldK, Not(Equals), csI0.k)
	csR0.Rekey()

	clientMessage = []byte("hello again")
	msg = csI0.Encrypt(nil, nil, clientMessage)
	res, err = csR0.Decrypt(nil, nil, msg)
	c.Assert(string(clientMessage), Equals, string(res))

	serverMessage := []byte("bye")
	msg = csR1.Encrypt(nil, nil, serverMessage)
	res, err = csI1.Decrypt(nil, nil, msg)
	c.Assert(string(serverMessage), Equals, string(res))

	csR1.Rekey()
	csI1.Rekey()

	serverMessage = []byte("bye bye")
	msg = csR1.Encrypt(nil, nil, serverMessage)
	res, err = csI1.Decrypt(nil, nil, msg)
	c.Assert(string(serverMessage), Equals, string(res))

	// only rekey one side, test for failure
	csR1.Rekey()
	serverMessage = []byte("bye again")
	msg = csR1.Encrypt(nil, nil, serverMessage)
	res, err = csI1.Decrypt(nil, nil, msg)
	c.Assert(string(serverMessage), Not(Equals), string(res))
}
