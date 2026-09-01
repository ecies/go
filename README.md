# eciesgo

![Go](https://github.com/ecies/go/actions/workflows/go.yml/badge.svg)
[![GoDoc Widget](https://godoc.org/github.com/ecies/go?status.svg)](https://godoc.org/github.com/ecies/go)
[![Go Report](https://goreportcard.com/badge/github.com/ecies/go)](https://goreportcard.com/report/github.com/ecies/go)

Elliptic Curve Integrated Encryption Scheme for secp256k1, written in Go with **minimal** dependencies.

This is the Go version of [ecies/py](https://github.com/ecies/py) with a built-in class-like secp256k1 API, you may go there for detailed documentation of the mechanism under the hood.

## Install
`go get github.com/ecies/go/v2`

Go 1.13 is required cause `fmt.Errorf` is used to wrap errors.

> ⚠️ Please use version 2.0.3 and later. It's much faster and safer.

## Quick Start
```go
package main

import (
	ecies "github.com/ecies/go/v2"
	"log"
)

func main() {
	k, err := ecies.GenerateKey()
	if err != nil {
		panic(err)
	}
	log.Println("key pair has been generated")

	ciphertext, err := ecies.Encrypt(k.PublicKey, []byte("THIS IS THE TEST"))
	if err != nil {
		panic(err)
	}
	log.Printf("plaintext encrypted: %v\n", ciphertext)

	plaintext, err := ecies.Decrypt(k, ciphertext)
	if err != nil {
		panic(err)
	}
	log.Printf("ciphertext decrypted: %s\n", string(plaintext))
}
```

## CLI
`valicrypter` (validator encrypter) is a minimal command line tool for encrypting to a public key
and decrypting with a private key. Input is passed as an argument, output goes to stdout.

```sh
go install github.com/chronicleprotocol/ecies/cmd/valicrypter@latest
```

```sh
# Encrypt a plaintext to a recipient, ciphertext hex to stdout
valicrypter -r <pubkey-hex> 'THIS IS THE TEST' > ciphertext.hex

# Decrypt a ciphertext hex, plaintext to stdout
valicrypter -d -i <privkey-hex> "$(cat ciphertext.hex)"
```

The recipient public key is hex, either 33-byte compressed or 65-byte uncompressed. Keys may be
given with or without a `0x` prefix. Note that `-i` puts the private key into your shell history and
process listing.

## Benchmarks
With CGO:
```
goos: linux
goarch: amd64
pkg: github.com/ecies/go/v2
cpu: AMD Ryzen 7 5700G with Radeon Graphics         
BenchmarkEncrypt-16        12250             98122 ns/op            5185 B/op         61 allocs/op
BenchmarkDecrypt-16        23934             50046 ns/op            4097 B/op         46 allocs/op
```

Without CGO:
```
goos: linux
goarch: amd64
pkg: github.com/ecies/go/v2
cpu: AMD Ryzen 7 5700G with Radeon Graphics         
BenchmarkEncrypt-16        10000            112632 ns/op            5655 B/op         68 allocs/op
BenchmarkDecrypt-16        14038             85641 ns/op            4725 B/op         56 allocs/op
```