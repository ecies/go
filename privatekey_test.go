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
	if !assert.NoError(t, err) {
		return
	}

	privkey.Hex()
}

func TestPrivateKey_Equals(t *testing.T) {
	privkey, err := GenerateKey()
	if !assert.NoError(t, err) {
		return
	}

	assert.True(t, privkey.Equals(privkey))
}

func TestPrivateKey_UnsafeECDH(t *testing.T) {
	privkey1, err := GenerateKey()
	if !assert.NoError(t, err) {
		return
	}
	privkey2, err := GenerateKey()
	if !assert.NoError(t, err) {
		return
	}

	ss1, err := privkey1.ECDH(privkey2.PublicKey)
	if !assert.NoError(t, err) {
		return
	}
	ss2, err := privkey2.ECDH(privkey1.PublicKey)
	if !assert.NoError(t, err) {
		return
	}

	assert.Equal(t, subtle.ConstantTimeCompare(ss1, ss2), 1)
}
