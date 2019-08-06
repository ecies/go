package eciesgo

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"github.com/L11R/eciesgo/secp256k1"
	"github.com/pkg/errors"
	"math/big"
)

func Encrypt(receiverPubhex string, msg []byte) ([]byte, error) {
	// Generate ephemeral key
	dk, err := GenerateKey()
	if err != nil {
		return nil, err
	}

	// Receiver public key in hex
	rpk, err := NewPublicKeyFromHex(receiverPubhex)
	if err != nil {
		return nil, err
	}

	// Derive common secret
	cs := dk.ECDH(rpk)

	// AES encryption
	block, err := aes.NewCipher(cs)
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

	return bytes.Join([][]byte{dk.PublicKey.Bytes(), nonce, tag, ciphertext}, nil), nil
}

func Decrypt(receiverPrivhex string, msg []byte) ([]byte, error) {
	// Receiver private key
	rpk, err := NewPrivateKeyFromHex(receiverPrivhex)
	if err != nil {
		return nil, err
	}

	// Disposable sender public key
	dpk := &PublicKey{
		Curve: secp256k1.S256(),
		X:     new(big.Int).SetBytes(msg[1:33]),
		Y:     new(big.Int).SetBytes(msg[33:65]),
	}

	ciphertext := msg[65:]

	// Derive common secret
	cs := rpk.ECDH(dpk)

	// AES Decryption
	nonce := ciphertext[:16]
	tag := ciphertext[16:32]
	ciphertext = bytes.Join([][]byte{ciphertext[32:], tag}, nil)

	block, err := aes.NewCipher(cs)
	if err != nil {
		return nil, errors.Wrap(err, "cannot create new aes block")
	}

	aesgcm, err := cipher.NewGCMWithNonceSize(block, 16)
	if err != nil {
		return nil, errors.Wrap(err, "cannot create aes gcm")
	}

	plaintext, err := aesgcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, errors.Wrap(err, "cannot decrypt ciphertext")
	}

	return plaintext, nil
}
