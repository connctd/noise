// Package noise implements the Noise Protocol Framework.
//
// Noise is a low-level framework for building crypto protocols. Noise protocols
// support mutual and optional authentication, identity hiding, forward secrecy,
// zero round-trip encryption, and other advanced features. For more details,
// visit https://noiseprotocol.org.
package noise

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"math"
)

// A CipherState provides symmetric encryption and decryption after a successful
// handshake.
type CipherState struct {
	cs CipherSuite
	c  Cipher
	k  [32]byte
	n  uint64

	invalid bool
}

// Encrypt encrypts the plaintext and then appends the ciphertext and an
// authentication tag across the ciphertext and optional authenticated data to
// out. This method automatically increments the nonce after every call, so
// messages must be decrypted in the same order.
func (s *CipherState) Encrypt(out, ad, plaintext []byte) []byte {
	if s.invalid {
		panic("noise: CipherSuite has been copied, state is invalid")
	}
	out = s.c.Encrypt(out, s.n, ad, plaintext)
	s.n++
	return out
}

// Decrypt checks the authenticity of the ciphertext and authenticated data and
// then decrypts and appends the plaintext to out. This method automatically
// increments the nonce after every call, messages must be provided in the same
// order that they were encrypted with no missing messages.
func (s *CipherState) Decrypt(out, ad, ciphertext []byte) ([]byte, error) {
	if s.invalid {
		panic("noise: CipherSuite has been copied, state is invalid")
	}
	out, err := s.c.Decrypt(out, s.n, ad, ciphertext)
	s.n++
	return out, err
}

// Cipher returns the low-level symmetric encryption primitive. It should only
// be used if nonces need to be managed manually, for example with a network
// protocol that can deliver out-of-order messages. This is dangerous, users
// must ensure that they are incrementing a nonce after every encrypt operation.
// After calling this method, it is an error to call Encrypt/Decrypt on the
// CipherState.
func (s *CipherState) Cipher() Cipher {
	s.invalid = true
	return s.c
}

func (s *CipherState) Rekey() {
	var zeros [32]byte
	var out []byte
	out = s.c.Encrypt(out, math.MaxUint64, []byte{}, zeros[:])
	copy(s.k[:], out[:32])
	s.c = s.cs.Cipher(s.k)
}

type symmetricState struct {
	CipherState
	hasK bool
	ck   []byte
	h    []byte

	prevCK []byte
	prevH  []byte
}

func (s *symmetricState) InitializeSymmetric(handshakeName []byte) {
	h := s.cs.Hash()
	if len(handshakeName) <= h.Size() {
		s.h = make([]byte, h.Size())
		copy(s.h, handshakeName)
	} else {
		h.Write(handshakeName)
		s.h = h.Sum(nil)
	}
	s.ck = make([]byte, len(s.h))
	copy(s.ck, s.h)
}

func (s *symmetricState) MixKey(dhOutput []byte) {
	s.n = 0
	s.hasK = true
	var hk []byte
	s.ck, hk, _ = hkdf(s.cs.Hash, 2, s.ck[:0], s.k[:0], nil, s.ck, dhOutput)
	copy(s.k[:], hk)
	s.c = s.cs.Cipher(s.k)
}

func (s *symmetricState) MixHash(data []byte) {
	h := s.cs.Hash()
	h.Write(s.h)
	h.Write(data)
	s.h = h.Sum(s.h[:0])
}

func (s *symmetricState) MixKeyAndHash(data []byte) {
	var hk []byte
	var temp []byte
	s.ck, temp, hk = hkdf(s.cs.Hash, 3, s.ck[:0], temp, s.k[:0], s.ck, data)
	s.MixHash(temp)
	copy(s.k[:], hk)
	s.c = s.cs.Cipher(s.k)
	s.n = 0
	s.hasK = true
}

func (s *symmetricState) EncryptAndHash(out, plaintext []byte) []byte {
	if !s.hasK {
		s.MixHash(plaintext)
		return append(out, plaintext...)
	}
	ciphertext := s.Encrypt(out, s.h, plaintext)
	s.MixHash(ciphertext[len(out):])
	return ciphertext
}

func (s *symmetricState) DecryptAndHash(out, data []byte) ([]byte, error) {
	if !s.hasK {
		s.MixHash(data)
		return append(out, data...), nil
	}
	plaintext, err := s.Decrypt(out, s.h, data)
	if err != nil {
		return nil, err
	}
	s.MixHash(data)
	return plaintext, nil
}

func (s *symmetricState) Split() (*CipherState, *CipherState) {
	s1, s2 := &CipherState{cs: s.cs}, &CipherState{cs: s.cs}
	hk1, hk2, _ := hkdf(s.cs.Hash, 2, s1.k[:0], s2.k[:0], nil, s.ck, nil)
	copy(s1.k[:], hk1)
	copy(s2.k[:], hk2)
	s1.c = s.cs.Cipher(s1.k)
	s2.c = s.cs.Cipher(s2.k)
	return s1, s2
}

func (s *symmetricState) Checkpoint() {
	if len(s.ck) > cap(s.prevCK) {
		s.prevCK = make([]byte, len(s.ck))
	}
	s.prevCK = s.prevCK[:len(s.ck)]
	copy(s.prevCK, s.ck)

	if len(s.h) > cap(s.prevH) {
		s.prevH = make([]byte, len(s.h))
	}
	s.prevH = s.prevH[:len(s.h)]
	copy(s.prevH, s.h)
}

func (s *symmetricState) Rollback() {
	s.ck = s.ck[:len(s.prevCK)]
	copy(s.ck, s.prevCK)
	s.h = s.h[:len(s.prevH)]
	copy(s.h, s.prevH)
}

// A MessagePattern is a single message or operation used in a Noise handshake.
type MessagePattern int

// A HandshakePattern is a list of messages and operations that are used to
// perform a specific Noise handshake.
type HandshakePattern struct {
	Name                 string
	InitiatorPreMessages []MessagePattern
	ResponderPreMessages []MessagePattern
	Messages             [][]MessagePattern
}

const (
	// MessagePatternS Appends EncryptAndHash(s.public_key) to the buffer.
	//
	// Sets temp to the next DHLEN + 16 bytes of the message if HasKey() == True, or to the next DHLEN bytes otherwise. Sets rs (which must be empty) to DecryptAndHash(temp).
	MessagePatternS MessagePattern = iota
	// MessagePatternE Sets e (which must be empty) to GENERATE_KEYPAIR().
	// Appends e.public_key to the buffer. Calls MixHash(e.public_key)
	//
	// Sets re (which must be empty) to the next DHLEN bytes from the message. Calls MixHash(re.public_key).
	MessagePatternE
	// MessagePatternDHEE Calls MixKey(DH(e, re)).
	//
	// Calls MixKey(DH(e, re)).
	MessagePatternDHEE
	// MessagePatternDHES Calls MixKey(DH(e, rs)) if initiator, MixKey(DH(s, re)) if responder.
	//
	// Calls MixKey(DH(e, rs)) if initiator, MixKey(DH(s, re)) if responder.
	MessagePatternDHES
	// MessagePatternDHSE Calls MixKey(DH(s, re)) if initiator, MixKey(DH(e, rs)) if responder.
	//
	// Calls MixKey(DH(s, re)) if initiator, MixKey(DH(e, rs)) if responder.
	MessagePatternDHSE
	// MessagePatternDHSS Calls MixKey(DH(s, rs)).
	//
	// Calls MixKey(DH(s, rs)).
	MessagePatternDHSS
	// MessagePatternPSK for PresharedKey
	MessagePatternPSK
)

// MaxMsgLen is the maximum number of bytes that can be sent in a single Noise
// message.
const MaxMsgLen = 65535

// A HandshakeState tracks the state of a Noise handshake. It may be discarded
// after the handshake is complete.
type HandshakeState struct {
	ss                symmetricState
	s                 PrivateIdentity // local static keypair
	e                 DHKey           // local ephemeral keypair
	rs                Identity        // remote party's static public key
	re                []byte          // remote party's ephemeral public key
	psk               []byte          // preshared key, maybe zero length
	messagePatterns   [][]MessagePattern
	shouldWrite       bool
	initiator         bool
	msgIdx            int
	rng               io.Reader
	identityMarshaler IdentityMarshaler
	idVerifier        IdentityVerifier
}

// A Config provides the details necessary to process a Noise handshake. It is
// never modified by this package, and can be reused.
type Config struct {
	// CipherSuite is the set of cryptographic primitives that will be used.
	CipherSuite CipherSuite

	// Random is the source for cryptographically appropriate random bytes. If
	// zero, it is automatically configured.
	Random io.Reader

	// Pattern is the pattern for the handshake.
	Pattern HandshakePattern

	// Initiator must be true if the first message in the handshake will be sent
	// by this peer.
	Initiator bool

	// Prologue is an optional message that has already be communicated and must
	// be identical on both sides for the handshake to succeed.
	Prologue []byte

	// PresharedKey is the optional preshared key for the handshake.
	PresharedKey []byte

	// PresharedKeyPlacement specifies the placement position of the PSK token
	// when PresharedKey is specified
	PresharedKeyPlacement int

	// StaticKeypair is this peer's static keypair, required if part of the
	// handshake.
	StaticKeypair PrivateIdentity

	// EphemeralKeypair is this peer's ephemeral keypair that was provided as
	// a pre-message in the handshake.
	EphemeralKeypair DHKey

	// PeerStatic is the static public key of the remote peer that was provided
	// as a pre-message in the handshake.
	PeerStatic Identity

	// PeerEphemeral is the ephemeral public key of the remote peer that was
	// provided as a pre-message in the handshake.
	PeerEphemeral []byte

	// IdMarshaller allows you to use more complex IDs than plain public keys, i.e. certificates.
	// This parameter is optional.
	IDMarshaler IdentityMarshaler

	// IDVerifier can optionally be set to verify the remote identity.
	IDVerifier IdentityVerifier
}

// NewHandshakeState starts a new handshake using the provided configuration.
func NewHandshakeState(c Config) (*HandshakeState, error) {
	hs := &HandshakeState{
		s:                 c.StaticKeypair,
		e:                 c.EphemeralKeypair,
		rs:                c.PeerStatic,
		psk:               c.PresharedKey,
		messagePatterns:   c.Pattern.Messages,
		shouldWrite:       c.Initiator,
		initiator:         c.Initiator,
		rng:               c.Random,
		identityMarshaler: c.IDMarshaler,
		idVerifier:        c.IDVerifier,
	}
	if hs.identityMarshaler == nil {
		// Assume that the usual plain public keys are used
		hs.identityMarshaler = simpleIdentityMarshaler{}
	}
	if hs.rng == nil {
		hs.rng = rand.Reader
	}
	if len(c.PeerEphemeral) > 0 {
		hs.re = make([]byte, len(c.PeerEphemeral))
		copy(hs.re, c.PeerEphemeral)
	}
	hs.ss.cs = c.CipherSuite
	pskModifier := ""
	if len(hs.psk) > 0 {
		if len(hs.psk) != 32 {
			return nil, errors.New("noise: specification mandates 256-bit preshared keys")
		}
		pskModifier = fmt.Sprintf("psk%d", c.PresharedKeyPlacement)
		hs.messagePatterns = append([][]MessagePattern(nil), hs.messagePatterns...)
		if c.PresharedKeyPlacement == 0 {
			hs.messagePatterns[0] = append([]MessagePattern{MessagePatternPSK}, hs.messagePatterns[0]...)
		} else {
			hs.messagePatterns[c.PresharedKeyPlacement-1] = append(hs.messagePatterns[c.PresharedKeyPlacement-1], MessagePatternPSK)
		}
	}
	hs.ss.InitializeSymmetric([]byte("Noise_" + c.Pattern.Name + pskModifier + "_" + string(hs.ss.cs.Name())))
	hs.ss.MixHash(c.Prologue)
	for _, m := range c.Pattern.InitiatorPreMessages {
		switch {
		case c.Initiator && m == MessagePatternS:
			hs.ss.MixHash(hs.s.PublicKey())
		case c.Initiator && m == MessagePatternE:
			hs.ss.MixHash(hs.e.Public)
		case !c.Initiator && m == MessagePatternS:
			if err := hs.eventuallyVerifyIdentity(hs.rs); err != nil {
				return nil, err
			}
			hs.ss.MixHash(hs.rs.PublicKey())
		case !c.Initiator && m == MessagePatternE:
			hs.ss.MixHash(hs.re)
		}
	}
	for _, m := range c.Pattern.ResponderPreMessages {
		switch {
		case !c.Initiator && m == MessagePatternS:
			hs.ss.MixHash(hs.s.PublicKey())
		case !c.Initiator && m == MessagePatternE:
			hs.ss.MixHash(hs.e.Public)
		case c.Initiator && m == MessagePatternS:
			if err := hs.eventuallyVerifyIdentity(hs.rs); err != nil {
				return nil, err
			}
			hs.ss.MixHash(hs.rs.PublicKey())
		case c.Initiator && m == MessagePatternE:
			hs.ss.MixHash(hs.re)
		}
	}
	return hs, nil
}

func (hs *HandshakeState) eventuallyVerifyIdentity(id Identity) error {
	if hs.idVerifier == nil {
		return nil
	}
	err := hs.idVerifier.VerifyIdentity(id)
	if err != nil {
		return fmt.Errorf("Verification of remote identity failed: %w", err)
	}
	return nil
}

// WriteMessage appends a handshake message to out. The message will include the
// optional payload if provided. If the handshake is completed by the call, two
// CipherStates will be returned, one is used for encryption of messages to the
// remote peer, the other is used for decryption of messages from the remote
// peer. It is an error to call this method out of sync with the handshake
// pattern.
func (s *HandshakeState) WriteMessage(out WriteableHandshakeMessage, payload []byte) (*CipherState, *CipherState, error) {
	if !s.shouldWrite {
		return nil, nil, errors.New("noise: unexpected call to WriteMessage should be ReadMessage")
	}
	if s.msgIdx > len(s.messagePatterns)-1 {
		return nil, nil, errors.New("noise: no handshake messages left")
	}
	if len(payload) > MaxMsgLen {
		return nil, nil, errors.New("noise: message is too long")
	}

	for _, msg := range s.messagePatterns[s.msgIdx] {
		switch msg {
		case MessagePatternE:
			e, err := s.ss.cs.GenerateKeypair(s.rng)
			if err != nil {
				return nil, nil, err
			}
			s.e = e
			out.WriteEPublic(s.e.Public)
			s.ss.MixHash(s.e.Public)
			if len(s.psk) > 0 {
				s.ss.MixKey(s.e.Public)
			}
		case MessagePatternS:
			if len(s.s.PublicKey()) == 0 {
				return nil, nil, errors.New("noise: invalid state, s.Public is nil")
			}
			idBytes, err := s.identityMarshaler.MarshalIdentity(s.s)
			if err != nil {
				return nil, nil, fmt.Errorf("Unable to marshal static identity: %w", err)
			}
			var encryptedSPublic []byte
			encryptedSPublic = s.ss.EncryptAndHash(encryptedSPublic, idBytes)
			out.WriteEncryptedIdentity(encryptedSPublic)
		case MessagePatternDHEE:
			s.ss.MixKey(s.ss.cs.DH(s.e.Private, s.re))
		case MessagePatternDHES:
			if s.initiator {
				s.ss.MixKey(s.ss.cs.DH(s.e.Private, s.rs.PublicKey()))
			} else {
				s.ss.MixKey(s.ss.cs.DH(s.s.PrivateKey(), s.re))
			}
		case MessagePatternDHSE:
			if s.initiator {
				s.ss.MixKey(s.ss.cs.DH(s.s.PrivateKey(), s.re))
			} else {
				s.ss.MixKey(s.ss.cs.DH(s.e.Private, s.rs.PublicKey()))
			}
		case MessagePatternDHSS:
			s.ss.MixKey(s.ss.cs.DH(s.s.PrivateKey(), s.rs.PublicKey()))
		case MessagePatternPSK:
			s.ss.MixKeyAndHash(s.psk)
		}
	}
	s.shouldWrite = false
	s.msgIdx++
	var encryptedPayload []byte
	encryptedPayload = s.ss.EncryptAndHash(encryptedPayload, payload)
	out.WriteEncryptedPayload(encryptedPayload)

	if s.msgIdx >= len(s.messagePatterns) {
		cs1, cs2 := s.ss.Split()
		return cs1, cs2, nil
	}

	return nil, nil, nil
}

// ErrShortMessage is returned by ReadMessage if a message is not as long as it should be.
var ErrShortMessage = errors.New("noise: message is too short")

// ReadMessage processes a received handshake message and appends the payload,
// if any to out. If the handshake is completed by the call, two CipherStates
// will be returned, one is used for encryption of messages to the remote peer,
// the other is used for decryption of messages from the remote peer. It is an
// error to call this method out of sync with the handshake pattern.
func (s *HandshakeState) ReadMessage(out []byte, message ReadableHandshakeMessage) ([]byte, *CipherState, *CipherState, error) {
	if s.shouldWrite {
		return nil, nil, nil, errors.New("noise: unexpected call to ReadMessage should be WriteMessage")
	}
	if s.msgIdx > len(s.messagePatterns)-1 {
		return nil, nil, nil, errors.New("noise: no handshake messages left")
	}

	s.ss.Checkpoint()

	var err error
	for _, msg := range s.messagePatterns[s.msgIdx] {
		switch msg {
		case MessagePatternE, MessagePatternS:
			expected := s.ss.cs.DHLen()
			if msg == MessagePatternS && s.ss.hasK {
				expected += 16
			}
			if message.Length() < expected {
				return nil, nil, nil, ErrShortMessage
			}
			switch msg {
			case MessagePatternE:
				if cap(s.re) < s.ss.cs.DHLen() {
					s.re = make([]byte, s.ss.cs.DHLen())
				}
				s.re = s.re[:s.ss.cs.DHLen()]
				s.re, err = message.ReadEPublic()
				if err != nil {
					return nil, nil, nil, err
				}
				s.ss.MixHash(s.re)
				if len(s.psk) > 0 {
					s.ss.MixKey(s.re)
				}
			case MessagePatternS:
				if s.rs != nil {
					return nil, nil, nil, errors.New("noise: invalid state, rs is not nil")
				}
				idBytes, err := message.ReadEncryptedIdentity()
				if err != nil {
					return nil, nil, nil, err
				}
				var decryptedRawIdentity []byte
				decryptedRawIdentity, err = s.ss.DecryptAndHash(decryptedRawIdentity, idBytes)
				if err != nil {
					return nil, nil, nil, fmt.Errorf("Failed to decrypt remote identity: %w", err)
				}
				identity, err := s.identityMarshaler.UnmarshalIdentity(decryptedRawIdentity)
				if err != nil {
					return nil, nil, nil, fmt.Errorf("Failed to unmarshal remote identity: %w", err)
				}
				if err := s.eventuallyVerifyIdentity(identity); err != nil {
					return nil, nil, nil, err
				}
				s.rs = identity
			}
			if err != nil {
				s.ss.Rollback()
				return nil, nil, nil, err
			}
			// FIXME probably we need to remove
			//message = message[expected:]
		case MessagePatternDHEE:
			s.ss.MixKey(s.ss.cs.DH(s.e.Private, s.re))
		case MessagePatternDHES:
			if s.initiator {
				s.ss.MixKey(s.ss.cs.DH(s.e.Private, s.rs.PublicKey()))
			} else {
				s.ss.MixKey(s.ss.cs.DH(s.s.PrivateKey(), s.re))
			}
		case MessagePatternDHSE:
			if s.initiator {
				s.ss.MixKey(s.ss.cs.DH(s.s.PrivateKey(), s.re))
			} else {
				s.ss.MixKey(s.ss.cs.DH(s.e.Private, s.rs.PublicKey()))
			}
		case MessagePatternDHSS:
			s.ss.MixKey(s.ss.cs.DH(s.s.PrivateKey(), s.rs.PublicKey()))
		case MessagePatternPSK:
			s.ss.MixKeyAndHash(s.psk)
		}
	}
	msgBytes, err := message.ReadPayload()
	if err != nil {
		return nil, nil, nil, fmt.Errorf("Failed to read payload from received handshake packet: %w", err)
	}
	out, err = s.ss.DecryptAndHash(out, msgBytes)
	if err != nil {
		s.ss.Rollback()
		return nil, nil, nil, fmt.Errorf("Failed to decrypt payload: %w", err)
	}
	s.shouldWrite = true
	s.msgIdx++

	if s.msgIdx >= len(s.messagePatterns) {
		cs1, cs2 := s.ss.Split()
		return out, cs1, cs2, nil
	}

	return out, nil, nil, nil
}

// ChannelBinding provides a value that uniquely identifies the session and can
// be used as a channel binding. It is an error to call this method before the
// handshake is complete.
func (s *HandshakeState) ChannelBinding() []byte {
	return s.ss.h
}

// PeerIdentity returns the static identity provided by the remote peer
// during a handshake. It is an error to call this method if a handshake message
// containing the static identity has not been read.
func (s *HandshakeState) PeerIdentity() Identity {
	return s.rs
}

// MessageIndex returns the current handshake message id
func (s *HandshakeState) MessageIndex() int {
	return s.msgIdx
}

// PeerEphemeral returns the ephemeral key provided by the remote peer during
// a handshake. It is an error to call this method if a handshake message
// containing a static key has not been read.
func (s *HandshakeState) PeerEphemeral() []byte {
	return s.re
}

// LocalEphemeral returns the local ephemeral key pair generated during
// a handshake.
func (s *HandshakeState) LocalEphemeral() DHKey {
	return s.e
}
