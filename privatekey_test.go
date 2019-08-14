package eciesgo

import (
	"crypto/subtle"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestNewPrivateKeyFromHex(t *testing.T) {
	_, err := NewPrivateKeyFromHex(testingReceiverPrivkeyHex)
	assert.NoError(t, err)
}

func TestPrivateKey_Hex(t *testing.T) {
	privkey, err := GenerateKey()
	assert.NoError(t, err)

	privkey.Hex()
}

func TestPrivateKey_Equals(t *testing.T) {
	privkey, err := GenerateKey()
	assert.NoError(t, err)

	assert.True(t, privkey.Equals(privkey))
}

func TestPrivateKey_UnsafeECDH(t *testing.T) {
	privkey1, err := GenerateKey()
	assert.NoError(t, err)
	privkey2, err := GenerateKey()
	assert.NoError(t, err)

	ss1, err := privkey1.ECDH(privkey2.PublicKey)
	assert.NoError(t, err)
	ss2, err := privkey2.ECDH(privkey1.PublicKey)
	assert.NoError(t, err)

	assert.Equal(t, subtle.ConstantTimeCompare(ss1, ss2), 1)
}
