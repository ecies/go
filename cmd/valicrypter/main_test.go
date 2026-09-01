package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

const testingMessage = "helloworld"
const testingReceiverPubkeyHex = "0498afe4f150642cd05cc9d2fa36458ce0a58567daeaf5fde7333ba9b403011140a4e28911fcf83ab1f457a30b4959efc4b9306f514a4c3711a16a80e3b47eb58b"
const testingReceiverPrivkeyHex = "95d3c5e483e9b1d4f5fc8e79b2deaf51362980de62dbb082a9a4257eef653d7d"

func TestRunEncryptAndDecrypt(t *testing.T) {
	var ciphertext bytes.Buffer
	err := run([]string{"-r", testingReceiverPubkeyHex, testingMessage}, &ciphertext)
	if !assert.NoError(t, err) {
		return
	}

	// Ciphertext is hex of the 97 byte envelope plus the message, newline terminated
	assert.Len(t, ciphertext.String(), 2*(97+len(testingMessage))+1)

	var plaintext bytes.Buffer
	err = run([]string{"-d", "-i", testingReceiverPrivkeyHex, ciphertext.String()}, &plaintext)
	if !assert.NoError(t, err) {
		return
	}

	assert.Equal(t, testingMessage, plaintext.String())
}

func TestRunEncryptAndDecryptMessageWithSpaces(t *testing.T) {
	message := " a message with spaces and\ttabs "

	var ciphertext bytes.Buffer
	err := run([]string{"-r", testingReceiverPubkeyHex, message}, &ciphertext)
	if !assert.NoError(t, err) {
		return
	}

	var plaintext bytes.Buffer
	err = run([]string{"-d", "-i", testingReceiverPrivkeyHex, ciphertext.String()}, &plaintext)
	if !assert.NoError(t, err) {
		return
	}

	assert.Equal(t, message, plaintext.String())
}

func TestRunStrips0xPrefix(t *testing.T) {
	var ciphertext bytes.Buffer
	err := run([]string{"-r", "0x" + testingReceiverPubkeyHex, testingMessage}, &ciphertext)
	if !assert.NoError(t, err) {
		return
	}

	var plaintext bytes.Buffer
	err = run([]string{"-d", "-i", "0x" + testingReceiverPrivkeyHex, "0x" + strings.TrimSpace(ciphertext.String())}, &plaintext)
	if !assert.NoError(t, err) {
		return
	}

	assert.Equal(t, testingMessage, plaintext.String())
}

func TestRunDecryptTrimsWhitespace(t *testing.T) {
	var ciphertext bytes.Buffer
	err := run([]string{"-r", testingReceiverPubkeyHex, testingMessage}, &ciphertext)
	if !assert.NoError(t, err) {
		return
	}

	padded := "\n  " + strings.TrimSpace(ciphertext.String()) + "  \n\n"

	var plaintext bytes.Buffer
	err = run([]string{"-d", "-i", testingReceiverPrivkeyHex, padded}, &plaintext)
	if !assert.NoError(t, err) {
		return
	}

	assert.Equal(t, testingMessage, plaintext.String())
}

func TestRunEncryptDashPrefixedInputAfterTerminator(t *testing.T) {
	message := "-not-a-flag"

	var ciphertext bytes.Buffer
	err := run([]string{"-r", testingReceiverPubkeyHex, "--", message}, &ciphertext)
	if !assert.NoError(t, err) {
		return
	}

	var plaintext bytes.Buffer
	err = run([]string{"-d", "-i", testingReceiverPrivkeyHex, "--", ciphertext.String()}, &plaintext)
	if !assert.NoError(t, err) {
		return
	}

	assert.Equal(t, message, plaintext.String())
}

func TestRunHelp(t *testing.T) {
	// -h is not an error and must not emit anything on stdout
	var stdout bytes.Buffer
	err := run([]string{"-h"}, &stdout)

	assert.NoError(t, err)
	assert.Empty(t, stdout.String())
}

func TestRunUndefinedFlag(t *testing.T) {
	assertRunFails(t, []string{"-z", testingMessage})
}

func TestRunMissingRecipient(t *testing.T) {
	assertRunFails(t, []string{testingMessage})
}

func TestRunMissingIdentity(t *testing.T) {
	assertRunFails(t, []string{"-d", testingMessage})
}

func TestRunRecipientWithDecrypt(t *testing.T) {
	assertRunFails(t, []string{"-d", "-r", testingReceiverPubkeyHex, "-i", testingReceiverPrivkeyHex, testingMessage})
}

func TestRunIdentityWithoutDecrypt(t *testing.T) {
	assertRunFails(t, []string{"-r", testingReceiverPubkeyHex, "-i", testingReceiverPrivkeyHex, testingMessage})
}

func TestRunMissingInputArgument(t *testing.T) {
	assertRunFails(t, []string{"-r", testingReceiverPubkeyHex})
}

func TestRunTooManyArguments(t *testing.T) {
	assertRunFails(t, []string{"-r", testingReceiverPubkeyHex, testingMessage, "extra"})
}

func TestRunEmptyInput(t *testing.T) {
	assertRunFails(t, []string{"-r", testingReceiverPubkeyHex, ""})
}

func TestRunInvalidRecipient(t *testing.T) {
	assertRunFails(t, []string{"-r", "not-a-public-key", testingMessage})
}

func TestRunInvalidIdentity(t *testing.T) {
	assertRunFails(t, []string{"-d", "-i", "not-a-private-key", testingMessage})
}

func TestRunInvalidCiphertextHex(t *testing.T) {
	assertRunFails(t, []string{"-d", "-i", testingReceiverPrivkeyHex, "zzzz"})
}

func TestRunTruncatedCiphertext(t *testing.T) {
	assertRunFails(t, []string{"-d", "-i", testingReceiverPrivkeyHex, strings.Repeat("ab", 97)})
}

// assertRunFails asserts that run returns an error and leaves stdout untouched
func assertRunFails(t *testing.T, args []string) {
	t.Helper()

	var stdout bytes.Buffer
	err := run(args, &stdout)

	assert.Error(t, err)
	assert.Empty(t, stdout.String())
}
