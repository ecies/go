package eciesgo

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

const testingMessage = "TESTING MESSAGE"
const testingReceiverPubkeyHex = "04153c0be4a73c4c5ef24970f0b7a6b4ac6e11bd790a5bc80e83e084d566a08f7dad13122402c2a17537e29f8bfa9c844d89c8ae980a90e202df254891058a7efa"
const testingReceiverPrivkeyHex = "3325919c42a8bdbdb013b11e9468198c9b2af8be796e10ae8f9448815e71db3a"

var testingReceiverPrivkey = []byte{51, 37, 145, 156, 66, 168, 189, 189, 176, 19, 177, 30, 148, 104, 25, 140, 155, 42, 248, 190, 121, 110, 16, 174, 143, 148, 72, 129, 94, 113, 219, 58}

func TestEncryptAndDecrypt(t *testing.T) {
	privkey := NewPrivateKeyFromBytes(testingReceiverPrivkey)

	ciphertext, err := Encrypt(privkey.PublicKey, []byte(testingMessage))
	assert.NoError(t, err)

	plaintext, err := Decrypt(privkey, ciphertext)
	assert.NoError(t, err)

	assert.Equal(t, testingMessage, string(plaintext))
}

func TestNewPublicKeyFromHex(t *testing.T) {
	_, err := NewPublicKeyFromHex(testingReceiverPubkeyHex)
	assert.NoError(t, err)
}

func TestNewPrivateKeyFromHex(t *testing.T) {
	_, err := NewPrivateKeyFromHex(testingReceiverPrivkeyHex)
	assert.NoError(t, err)
}

func TestGenerateKey(t *testing.T) {
	_, err := GenerateKey()
	assert.NoError(t, err)
}
