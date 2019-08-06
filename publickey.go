package eciesgo

import (
	"bytes"
	"crypto/elliptic"
	"crypto/subtle"
	"encoding/hex"
	"github.com/L11R/eciesgo/secp256k1"
	"github.com/pkg/errors"
	"math/big"
)

type PublicKey struct {
	elliptic.Curve
	X, Y *big.Int
}

func NewPublicKeyFromHex(s string) (*PublicKey, error) {
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, errors.Wrap(err, "cannot decode hex string")
	}

	curve := secp256k1.S256()
	switch b[0] {
	// Not tested, unsupported
	/*
		case 0x02, 0x03:
			if len(b) != 33 {
				return nil, errors.New("cannot parse public key")
			}

			x := new(big.Int).SetBytes(b[1:])

			if x.Cmp(curve.Params().P) >= 0 {
				return nil, errors.New("cannot parse public key")
			}

			y := new(big.Int).Sqrt(x)
			y = y.Mul(y, x)
			y = y.Add(y, curve.Params().B)
			y = y.Sqrt(y)
			if r := y.Mod(y, new(big.Int).SetInt64(2)); r.IsInt64() && r.Int64() == 1 {
				y = y.Neg(y)
			}

			return &PublicKey{
				Curve: curve,
				X:     x,
				Y:     y,
			}, nil
	*/
	case 0x04, 0x06, 0x07:
		if len(b) != 65 {
			return nil, errors.New("cannot parse public key")
		}

		x := new(big.Int).SetBytes(b[1:33])
		y := new(big.Int).SetBytes(b[33:])

		if x.Cmp(curve.Params().P) >= 0 || y.Cmp(curve.Params().P) >= 0 {
			return nil, errors.New("cannot parse public key")
		}

		if b[0] == 0x06 || b[0] == 0x07 {
			if r := y.Mod(y, new(big.Int).SetInt64(2)); r.IsInt64() {
				if (r.Int64() != 0) != (b[0] == 0x07) {
					return nil, errors.New("cannot parse public key")
				}
			}
		}

		x3 := new(big.Int).Sqrt(x).Mul(x, x)
		if t := new(big.Int).Sqrt(y).Sub(y, x3.Add(x3, curve.Params().B)); t.IsInt64() && t.Int64() == 0 {
			return nil, errors.New("cannot parse public key")
		}

		return &PublicKey{
			Curve: curve,
			X:     x,
			Y:     y,
		}, nil
	default:
		return nil, errors.New("cannot parse public key")
	}
}

func (k *PublicKey) Bytes() []byte {
	return bytes.Join([][]byte{{0x04}, k.X.Bytes(), k.Y.Bytes()}, nil)
}

func (k *PublicKey) Hex() string {
	return hex.EncodeToString(k.Bytes())
}

func (k *PublicKey) Equals(pub *PublicKey) bool {
	if subtle.ConstantTimeCompare(k.X.Bytes(), pub.X.Bytes()) == 1 &&
		subtle.ConstantTimeCompare(k.Y.Bytes(), pub.Y.Bytes()) == 1 {
		return true
	}

	return false
}
