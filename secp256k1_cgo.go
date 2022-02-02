//go:build cgo && !ecies_test_race
// +build cgo,!ecies_test_race

package eciesgo

import (
	"crypto/elliptic"

	"github.com/ethereum/go-ethereum/crypto/secp256k1"
)

func getCurve() elliptic.Curve {
	return secp256k1.S256()
}
