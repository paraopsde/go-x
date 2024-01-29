package crypto

import (
	"bytes"
	"fmt"
	"reflect"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestChachaSealOpenSmall(t *testing.T) {
	req := require.New(t)

	// trivial test
	k, err := NewKey()
	req.NoError(err, "key creation should succeed")
	if err != nil {
		t.Errorf("failed to create key: %v", err)
	}
	infile := []byte("Hello World")
	cipher, err := k.ChachaSeal(infile)
	if err != nil {
		t.Errorf("failed to seal: %v", err)
	}

	fmt.Printf("chacha seal done: %d\n", len(cipher))

	plain, err := k.ChachaOpen(cipher)
	req.NoError(err, "chacha open should succeed")
	if !reflect.DeepEqual(plain, infile) {
		t.Errorf("crypt-decrypt cycled failed.")
	}
}
func TestChachaSealOpenBigger(t *testing.T) {
	req := require.New(t)

	// trivial test
	k, err := NewKey()
	req.NoError(err, "key creation should succeed")

	infile := bytes.NewBuffer(make([]byte, 23*1024*1024))
	cipher, err := k.ChachaSeal(infile.Bytes())
	req.NoError(err, "chacha seal should succeed")

	fmt.Printf("chacha seal done: %d\n", len(cipher))

	plain, err := k.ChachaOpen(cipher)
	req.NoError(err, "chacha open should succeed")
	if !reflect.DeepEqual(plain, infile.Bytes()) {
		t.Errorf("crypt-decrypt cycled failed.")
	}
}

func TestNonces(t *testing.T) {
	fmt.Printf("nonce len: %d\nkey len: %d\n", nonceSize, keySize)

	primeNonce := []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11}
	fmt.Printf("nonce: %x\n", primeNonce)
	fmt.Printf("nonce+1: %x\n", CountedNonce(primeNonce, 1))
	fmt.Printf("nonce+2: %x\n", CountedNonce(primeNonce, 2))
	fmt.Printf("nonce+4: %x\n", CountedNonce(primeNonce, 4))
	fmt.Printf("nonce+256: %x\n", CountedNonce(primeNonce, 256))
	fmt.Printf("nonce: %x\n", primeNonce)

	if !reflect.DeepEqual(primeNonce, CountedNonce(primeNonce, 0)) {
		t.Errorf("expected unmodified primeNonce.")
	}

	fmt.Printf("nonce+3: %x\n", CountedNonce(primeNonce, 3))
	if !reflect.DeepEqual([]byte{3, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11}, CountedNonce(primeNonce, 3)) {
		t.Errorf("expected different counted nonce.")
	}

	fmt.Printf("nonce+4294967295: %x\n", CountedNonce(primeNonce, 4294967295))
	if !reflect.DeepEqual([]byte{0xff, 0xfe, 0xfd, 0xfc, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b},
		CountedNonce(primeNonce, 4294967295)) {
		t.Errorf("expected different counted nonce.")
	}

	shortNonce := [8]byte{}
	fmt.Printf("nonce8+3: %x\n", CountedNonce(shortNonce[:], 3))
}
