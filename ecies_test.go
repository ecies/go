package eciesgo

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

const testingMessage = "TESTING MESSAGE"
const testingReceiverPubHex = "04153c0be4a73c4c5ef24970f0b7a6b4ac6e11bd790a5bc80e83e084d566a08f7dad13122402c2a17537e29f8bfa9c844d89c8ae980a90e202df254891058a7efa"
const testingReceiverPrivHex = "3325919c42a8bdbdb013b11e9468198c9b2af8be796e10ae8f9448815e71db3a"

func TestEncryptAndDecrypt(t *testing.T) {
	ciphertext, err := Encrypt(testingReceiverPubHex, []byte(testingMessage))
	assert.NoError(t, err)

	plaintext, err := Decrypt(testingReceiverPrivHex, ciphertext)
	assert.NoError(t, err)

	assert.Equal(t, testingMessage, string(plaintext))
}

func TestGenerateKey(t *testing.T) {
	_, err := GenerateKey()
	assert.NoError(t, err)
}
