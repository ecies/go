package eciesgo

import (
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"github.com/L11R/eciesgo/secp256k1"
	"github.com/pkg/errors"
	"math/big"
)

type PrivateKey struct {
	PublicKey
	D *big.Int
}

func GenerateKey() (*PrivateKey, error) {
	curve := secp256k1.S256()

	p, x, y, err := elliptic.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, errors.Wrap(err, "cannot generate key pair")
	}

	return &PrivateKey{
		PublicKey: PublicKey{
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

	curve := secp256k1.S256()
	x, y := curve.ScalarBaseMult(b)

	return &PrivateKey{
		PublicKey: PublicKey{
			Curve: curve,
			X:     x,
			Y:     y,
		},
		D: new(big.Int).SetBytes(b),
	}, nil
}

func (k *PrivateKey) Bytes() []byte {
	return k.D.Bytes()
}

func (k *PrivateKey) Hex() string {
	return hex.EncodeToString(k.D.Bytes())
}

func (k *PrivateKey) ECDH(pub *PublicKey) []byte {
	sx, _ := pub.Curve.ScalarMult(pub.X, pub.Y, k.D.Bytes())

	h := sha256.New()
	if r := new(big.Int).Mod(sx, new(big.Int).SetInt64(2)); r.IsInt64() && r.Int64() != 0 {
		h.Write([]byte{0x03})
	} else {
		h.Write([]byte{0x02})
	}

	h.Write(sx.Bytes())
	return h.Sum(nil)
}

func (k *PrivateKey) Equals(priv *PrivateKey) bool {
	if subtle.ConstantTimeCompare(k.D.Bytes(), priv.D.Bytes()) == 1 {
		return true
	}

	return false
}
