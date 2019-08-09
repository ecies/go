package eciesgo

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"github.com/fomichev/secp256k1"
	"github.com/pkg/errors"
	"math/big"
)

// Encrypt encrypts a passed message with a receiver public key, returns ciphertext or encryption error
func Encrypt(pubkey *PublicKey, msg []byte) ([]byte, error) {
	// Generate ephemeral key
	ek, err := GenerateKey()
	if err != nil {
		return nil, err
	}

	// Derive shared secret
	ss, err := ek.ECDH(pubkey)
	if err != nil {
		return nil, err
	}

	// AES encryption
	block, err := aes.NewCipher(ss)
	if err != nil {
		return nil, errors.Wrap(err, "cannot create new aes block")
	}

	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return nil, errors.Wrap(err, "cannot read random bytes for nonce")
	}

	aesgcm, err := cipher.NewGCMWithNonceSize(block, 16)
	if err != nil {
		return nil, errors.Wrap(err, "cannot create aes gcm")
	}

	ciphertext := aesgcm.Seal(nil, nonce, msg, nil)
	tag := ciphertext[len(ciphertext)-aesgcm.NonceSize():]
	ciphertext = ciphertext[:len(ciphertext)-len(tag)]

	return bytes.Join([][]byte{ek.PublicKey.Bytes(false), nonce, tag, ciphertext}, nil), nil
}

// Decrypt decrypts a passed message with a receiver private key, returns plaintext or decryption error
func Decrypt(privkey *PrivateKey, msg []byte) ([]byte, error) {
	// Message cannot be less than length of public key (65) + nonce (16) + tag (16)
	if len(msg) <= (1 + 32 + 32 + 16 + 16) {
		return nil, errors.New("invalid length of message")
	}

	// Ephemeral sender public key
	ethPubkey := &PublicKey{
		Curve: secp256k1.SECP256K1(),
		X:     new(big.Int).SetBytes(msg[1:33]),
		Y:     new(big.Int).SetBytes(msg[33:65]),
	}

	// Shift message
	msg = msg[65:]

	// Derive shared secret
	ss, err := privkey.ECDH(ethPubkey)
	if err != nil {
		return nil, err
	}

	// AES decryption part
	nonce := msg[:16]
	tag := msg[16:32]

	// Create Golang-accepted ciphertext
	ciphertext := bytes.Join([][]byte{msg[32:], tag}, nil)

	block, err := aes.NewCipher(ss)
	if err != nil {
		return nil, errors.Wrap(err, "cannot create new aes block")
	}

	gcm, err := cipher.NewGCMWithNonceSize(block, 16)
	if err != nil {
		return nil, errors.Wrap(err, "cannot create gcm cipher")
	}

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, errors.Wrap(err, "cannot decrypt ciphertext")
	}

	return plaintext, nil
}
