// +build smolcert

package noise

import (
	"testing"
	"time"

	"github.com/connctd/smolcert"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPrivateIdentityKeyLength(t *testing.T) {
	rootCert, rootKey, err := smolcert.SelfSignedCertificate("root",
		time.Now(), time.Now().Add(time.Hour), []smolcert.Extension{})
	require.NoError(t, err)
	assert.NotEmpty(t, rootCert)
	assert.NotEmpty(t, rootKey)

	clientCert, clientKey, err := smolcert.SignedCertificate("client1",
		2, time.Now(), time.Now().Add(time.Hour), []smolcert.Extension{}, rootKey, rootCert.Subject)
	require.NoError(t, err)
	require.NotEmpty(t, clientCert)
	require.NotEmpty(t, clientKey)

	privateID := &PrivateSmolIdentity{SmolIdentity{*clientCert}, clientKey}
	assert.Len(t, privateID.PrivateKey(), 32)
}

func TestXXHandshakeWithIdentityVerifiction(t *testing.T) {
	rootCert, rootKey, err := smolcert.SelfSignedCertificate("root",
		time.Now(), time.Now().Add(time.Hour), []smolcert.Extension{})
	require.NoError(t, err)
	assert.NotEmpty(t, rootCert)
	assert.NotEmpty(t, rootKey)

	clientCert, clientKey, err := smolcert.SignedCertificate("client1",
		2, time.Now(), time.Now().Add(time.Hour), []smolcert.Extension{}, rootKey, rootCert.Subject)
	require.NoError(t, err)
	require.NotEmpty(t, clientCert)
	require.NotEmpty(t, clientKey)

	serverCert, serverKey, err := smolcert.SignedCertificate("server1",
		2, time.Now(), time.Now().Add(time.Hour), []smolcert.Extension{}, rootKey, rootCert.Subject)
	require.NoError(t, err)
	require.NotEmpty(t, serverCert)
	require.NotEmpty(t, serverKey)

	clientConfig := Config{
		Pattern:       HandshakeXX,
		Initiator:     true,
		StaticKeypair: &PrivateSmolIdentity{SmolIdentity{*clientCert}, clientKey},
	}

	clientHS, err := NewSmolHandshakeState(clientConfig, rootCert)
	require.NoError(t, err)
	assert.NotEmpty(t, clientHS)

	serverConfig := Config{
		Pattern:       HandshakeXX,
		CipherSuite:   NewCipherSuite(DH25519, CipherChaChaPoly, HashBLAKE2s),
		Initiator:     false,
		StaticKeypair: &PrivateSmolIdentity{SmolIdentity{*serverCert}, serverKey},
	}

	serverHS, err := NewSmolHandshakeState(serverConfig, rootCert)
	require.NoError(t, err)
	assert.NotEmpty(t, serverHS)

	msg := &SimpleMessage{}
	_, _, err = clientHS.WriteMessage(msg, nil)
	require.NoError(t, err)
	_, _, _, err = serverHS.ReadMessage(nil, msg)
	require.NoError(t, err)

	msg.Reset()
	_, _, err = serverHS.WriteMessage(msg, nil)
	require.NoError(t, err)
	_, _, _, err = clientHS.ReadMessage(nil, msg)
	require.NoError(t, err)

	msg.Reset()
	csI1, csI2, err := clientHS.WriteMessage(msg, nil)
	require.NoError(t, err)
	require.NotEmpty(t, csI1)
	require.NotEmpty(t, csI2)
	_, csR1, csR2, err := serverHS.ReadMessage(nil, msg)
	require.NoError(t, err)
	require.NotEmpty(t, csR1)
	require.NotEmpty(t, csR2)
}
