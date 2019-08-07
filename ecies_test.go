package eciesgo

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

const testingMessage = "this is a test"
const testingReceiverPubkeyHex =   "04b9a18af6814daa43fb9256b76623987171b7ce68779efe2511aef1060cf8af863b6bf7d50a4d3a9a75e06a471f0674a6cd68156afac8b4a692a37aaec7199d36"
const testingReceiverPrivkeyHex = "f07918f3f256183758ebfafe608afdad311567fc255d4fdaca78413b4f1a1904"

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
