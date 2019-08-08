package eciesgo

import (
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"github.com/fomichev/secp256k1"
	"github.com/pkg/errors"
	"math/big"
)

type PrivateKey struct {
	*PublicKey
	D *big.Int
}

func GenerateKey() (*PrivateKey, error) {
	curve := secp256k1.SECP256K1()

	p, x, y, err := elliptic.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, errors.Wrap(err, "cannot generate key pair")
	}

	return &PrivateKey{
		PublicKey: &PublicKey{
			Curve: curve,
			X:     x,
			Y:     y,
		},
		D: new(big.Int).SetBytes(p),
	}, nil
}

func NewPrivateKeyFromHex(s string) (*PrivateKey, error) {
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, errors.Wrap(err, "cannot decode hex string")
	}

	return NewPrivateKeyFromBytes(b), nil
}

func NewPrivateKeyFromBytes(priv []byte) *PrivateKey {
	curve := secp256k1.SECP256K1()
	x, y := curve.ScalarBaseMult(priv)

	return &PrivateKey{
		PublicKey: &PublicKey{
			Curve: curve,
			X:     x,
			Y:     y,
		},
		D: new(big.Int).SetBytes(priv),
	}
}

func (k *PrivateKey) Bytes() []byte {
	return k.D.Bytes()
}

func (k *PrivateKey) Hex() string {
	return hex.EncodeToString(k.D.Bytes())
}

func (k *PrivateKey) ECDH(pub *PublicKey) ([]byte, error) {
	if pub == nil {
		return nil, errors.New("public key is empty")
	}

	sx, sy := pub.Curve.ScalarMult(pub.X, pub.Y, k.D.Bytes())

	// SHA-256 KDF
	h := sha256.New()

	if sy.Bit(0) != 0 { // If odd
		h.Write([]byte{0x03})

	} else { // If even
		h.Write([]byte{0x02})
	}

	// Sometimes shared secret is less than 32 bytes; Big Endian
	length := len(pub.Curve.Params().P.Bytes())
	for i := 0; i < length-len(sx.Bytes()); i++ {
		h.Write([]byte{0})
	}

	h.Write(sx.Bytes())
	return h.Sum(nil), nil
}

func (k *PrivateKey) Equals(priv *PrivateKey) bool {
	if subtle.ConstantTimeCompare(k.D.Bytes(), priv.D.Bytes()) == 1 {
		return true
	}

	return false
}
