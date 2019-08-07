package eciesgo

import (
	"encoding/hex"
	"fmt"
	"github.com/stretchr/testify/assert"
	"testing"
)

const testingMessage = "this is a test"
const testingReceiverPubkeyHex = "0408a11bf9fb1b9344dba1d35c733f577f8c2a4c085b33dca914bf6d075e8480417871b265df20224e552438820ea01989aa481ebdbc926494143254331a5fd3db"

// const testingReceiverPubkeyHex =   "04b9a18af6814daa43fb9256b76623987171b7ce68779efe2511aef1060cf8af863b6bf7d50a4d3a9a75e06a471f0674a6cd68156afac8b4a692a37aaec7199d36"
// const testingReceiverPrivkeyHex = "3325919c42a8bdbdb013b11e9468198c9b2af8be796e10ae8f9448815e71db3a"
const testingReceiverPrivkeyHex = "f07918f3f256183758ebfafe608afdad311567fc255d4fdaca78413b4f1a1904"

const serverPrivHex = "aeba34f216f389fea66ff1aaabbb6c1e48d31de2c4e2b7b9157ffd650a773099"
const serverPubHex = "0494804a945fb6fa7226910beccc028a3bb2c8ab4431dd5e4e2477d351313da8d0c106e70af1c1c8792be11eeca693bb9ea2d618d8d8a6ebd79313e68ddb8d864d"
const encryted = "0443f124606380e23f0af6989500a53eeead2ef6144da861cf53ddff058e3655df2a697b91cb1907022d3b4382e0a62cf558b858593256c4284f5597cd6dd0da9daac4bce0d90d6fcc7fae4907204b2cdb096db013a578e4d1b0d4d0c91d17eee3bda56453a4f6195873759b6740a4"

var testingReceiverPrivkey = []byte{51, 37, 145, 156, 66, 168, 189, 189, 176, 19, 177, 30, 148, 104, 25, 140, 155, 42, 248, 190, 121, 110, 16, 174, 143, 148, 72, 129, 94, 113, 219, 58}

func TestDecrypt(t *testing.T) {
	k, _ := NewPrivateKeyFromHex(serverPrivHex)
	ciphertext, _ := hex.DecodeString(encryted)

	plaintext, err := Decrypt(k, ciphertext)
	assert.NoError(t, err)

	assert.Equal(t, testingMessage, string(plaintext))
}

func TestEncryptAndDecrypt(t *testing.T) {
	privkey := NewPrivateKeyFromBytes(testingReceiverPrivkey)
	fmt.Println(privkey.PublicKey.Hex())

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
