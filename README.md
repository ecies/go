# eciesgo

[![Build Status](https://travis-ci.com/ecies/go.svg)](https://travis-ci.com/ecies/go)
[![GoDoc Widget](https://godoc.org/github.com/ecies/go?status.svg)](https://godoc.org/github.com/ecies/go)
[![Go Report](https://goreportcard.com/badge/github.com/ecies/go)](https://goreportcard.com/report/github.com/ecies/go)

Elliptic Curve Integrated Encryption Scheme for secp256k1, written in Go with **minimal** dependencies.

This is the Go version of [ecies/py](https://github.com/ecies/py) with a built-in class-like secp256k1 API, you may go there for detailed documentation of the mechanism under the hood.

## Install
`go get github.com/ecies/go`

Go 1.13 is required cause `fmt.Errorf` is used to wrap errors.

## Quick Start
```go
package main

import (
	ecies "github.com/ecies/go"
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
