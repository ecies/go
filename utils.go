package eciesgo

import (
	"crypto/sha256"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
)

func kdf(secret []byte) (key []byte, err error) {
	key = make([]byte, 32)
	kdf := hkdf.New(sha256.New, secret, nil, nil)
	if _, err := io.ReadFull(kdf, key); err != nil {
		return nil, fmt.Errorf("cannot read secret from HKDF reader: %w", err)
	}

	return key, nil
}

func zeroPad(b []byte, length int) []byte {
	if len(b) > length {
		panic("bytes too long")
	}
	if len(b) < length {
		b = append(make([]byte, length-len(b)), b...)
	}
	return b
}
