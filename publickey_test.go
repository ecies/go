package eciesgo

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestNewPublicKeyFromHex(t *testing.T) {
	_, err := NewPublicKeyFromHex(testingReceiverPubkeyHex)
	assert.NoError(t, err)
}

func TestPublicKey_Equals(t *testing.T) {
	privkey, err := GenerateKey()
	assert.NoError(t, err)

	assert.True(t, privkey.PublicKey.Equals(privkey.PublicKey))
}
