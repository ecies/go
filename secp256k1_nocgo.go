//go:build !cgo
// +build !cgo

package eciesgo

import (
	"crypto/elliptic"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

func getCurve() elliptic.Curve {
	return secp256k1.S256()
}
