# eciesgo

[![Build Status](https://travis-ci.org/ecies/go.svg)](https://travis-ci.org/ecies/go)
[![GoDoc Widget](https://godoc.org/github.com/ecies/go?status.svg)](https://godoc.org/ecies/go)
[![Go Report](https://goreportcard.com/badge/github.com/ecies/go)](https://goreportcard.com/report/github.com/ecies/go)

Elliptic Curve Integrated Encryption Scheme for secp256k1, written in Go with **minimal** dependencies.

This is the Go version of [ecies/py](https://github.com/ecies/py) with a built-in class-like secp256k1 API, you may go there for detailed documentation of the mechanism under the hood.

## Install
`go get github.com/ecies/go`

## Quick Start
```go
package main

import (
	"github.com/ecies/go"
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
