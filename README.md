# eciesgo

[![Codacy Badge](https://api.codacy.com/project/badge/Grade/435dca6d9f5c4193bff07f203196d107)](https://app.codacy.com/app/L11R/eciesgo?utm_source=github.com&utm_medium=referral&utm_content=L11R/eciesgo&utm_campaign=Badge_Grade_Dashboard)

[![godoc widget]][godoc]

Elliptic Curve Integrated Encryption Scheme for secp256k1, written in Go with **minimal** dependencies.

This is the Go version of [eciespy](https://github.com/kigawas/eciespy) with a built-in class-like secp256k1 API, you may go there for detailed documentation of the mechanism under the hood.

## Install
`go get github.com/L11R/eciesgo`

## Quick Start
```go
package main

import (
	"github.com/L11R/eciesgo"
	"log"
)

func main() {
	k, err := eciesgo.GenerateKey()
	if err != nil {
		panic(err)
	}
	log.Println("key pair has been generated")

	ciphertext, err := eciesgo.Encrypt(k.PublicKey, []byte("THIS IS THE TEST"))
	if err != nil {
		panic(err)
	}
	log.Printf("plaintext encrypted: %v\n", ciphertext)

	plaintext, err := eciesgo.Decrypt(k, ciphertext)
	if err != nil {
		panic(err)
	}
	log.Printf("ciphertext decrypted: %s\n", string(plaintext))
}
```

[godoc]: https://godoc.org/github.com/L11R/eciesgo
[godoc widget]: https://godoc.org/github.com/L11R/eciesgo?status.svg
