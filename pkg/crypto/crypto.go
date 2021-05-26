package crypto

import (
	"bytes"
	"crypto/cipher"
	crand "crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
)

const (
	chunkSize int = 5 * 1024 * 1024
	nonceSize int = chacha20poly1305.NonceSize
	keySize   int = chacha20poly1305.KeySize
)

type Key struct {
	bytes [keySize]byte
	aead  cipher.AEAD
}

func NewKey() (*Key, error) {
	var keybytes [keySize]byte
	crand.Read(keybytes[:])
	return initKey(keybytes[:])
}

func NewKeyFromHex(hexstring string) (*Key, error) {
	keyBytes, err := hex.DecodeString(hexstring)
	if err != nil {
		return nil, fmt.Errorf("failed to decode hex: %v", err)
	}
	return initKey(keyBytes)
}

func NewKeyFromBytes(keybytes []byte) (*Key, error) {
	return initKey(keybytes)
}

func initKey(keybytes []byte) (*Key, error) {
	key := &Key{}
	copy(key.bytes[:], keybytes[:keySize])
	var err error
	key.aead, err = chacha20poly1305.New(keybytes)
	if err != nil {
		return nil, fmt.Errorf("failed to create aead: %v", err)
	}
	return key, nil
}

func CountedNonce(nonce []byte, counter uint64) []byte {
	if len(nonce) < 8 {
		return nil
	}
	newNonce := make([]byte, len(nonce))
	for idx, nonceByte := range nonce {
		if idx < 8 {
			newNonce[idx] = nonceByte ^ byte(counter&255)
			counter = counter >> 8
		} else {
			newNonce[idx] = nonceByte
		}
	}
	return newNonce
}

func (key *Key) ChachaOpenFromReader(cipherReader io.Reader, plainWriter io.Writer) error {
	var (
		nonce = make([]byte, chacha20poly1305.NonceSize)
		chunk []byte
	)
	chunk = make([]byte, chunkSize+key.aead.Overhead())
	idx := 0
	for eof := false; !eof; {
		// read chunk size and nonce
		buf := make([]byte, 8)
		n, err := io.ReadFull(cipherReader, buf)
		if err == io.EOF && n == 0 {
			return nil
		}
		if err != nil || n != 8 {
			return fmt.Errorf("failed to read header bytes (%d): %v", n, err)
		}
		thisChunkSize := binary.BigEndian.Uint64(buf)
		n, err = io.ReadFull(cipherReader, nonce)
		if err != nil || n != chacha20poly1305.NonceSize {
			return fmt.Errorf("failed to read nonce bytes (%d): %v", n, err)
		}

		// read cipher
		bytesRead, err := io.ReadFull(cipherReader, chunk[:thisChunkSize])
		if err != nil {
			return fmt.Errorf("failed to read %d bytes: %v", thisChunkSize, err)
		} else if uint64(bytesRead) != thisChunkSize {
			return fmt.Errorf("invalid size of chunk (%d) read: %v", bytesRead, err)
		}

		// open chunk
		plain, err := key.aead.Open(nil, nonce, chunk[:bytesRead], nil)
		if err != nil {
			return fmt.Errorf("failed to open chunk: %v", err)
		}

		// write plain
		bytesWritten, err := plainWriter.Write(plain)
		if bytesWritten > bytesRead || err != nil {
			return fmt.Errorf("failed to write (%d): %v", bytesWritten, err)
		}
		idx++
	}
	return nil
}
func (key *Key) ChachaSeal(plain []byte) ([]byte, error) {
	cipher := bytes.NewBuffer(make([]byte, 0, len(plain)+key.aead.Overhead()))
	err := key.ChachaSealFromReader(bytes.NewReader(plain), cipher)
	if err != nil {
		return nil, fmt.Errorf("failed to seal: %v", err)
	}
	return cipher.Bytes(), nil
}

func (key *Key) ChachaOpen(cipher []byte) ([]byte, error) {
	plain := bytes.NewBuffer(make([]byte, 0, len(cipher)))
	err := key.ChachaOpenFromReader(bytes.NewReader(cipher), plain)
	if err != nil {
		return nil, fmt.Errorf("failed to open: %v", err)
	}
	return plain.Bytes(), nil
}

func (key *Key) ChachaSealFromReader(plainReader io.Reader, cipherWriter io.Writer) error {
	var (
		primeNonce        = make([]byte, chacha20poly1305.NonceSize)
		chunk      []byte = make([]byte, chunkSize)
		nonceInc   uint64
	)
	crand.Read(primeNonce[:])

	for eof := false; !eof; {
		// read plain
		bytesRead, err := io.ReadFull(plainReader, chunk)
		if err != nil {
			if err != io.EOF && err != io.ErrUnexpectedEOF {
				return fmt.Errorf("failed to read %d bytes: %v", chunkSize, err)
			} else {
				//fmt.Printf("EOF encountered %d: %v (unexpected EOF is expected for last chunk)\n", bytesRead, err)
				eof = true
			}
		}

		if bytesRead == 0 {
			return nil
		}

		// seal chunk
		nonce := CountedNonce(primeNonce, nonceInc)
		nonceInc++
		cipher := key.aead.Seal(nil, nonce, chunk[:bytesRead], nil)

		// write nonce and chunk size (of cipher)
		buf := make([]byte, 8)
		binary.BigEndian.PutUint64(buf, uint64(len(cipher)))
		if n, e := cipherWriter.Write(buf); n != 8 || e != nil {
			panic("invalid chunk size length or unexpected error")
		}
		if n, e := cipherWriter.Write(nonce); n != chacha20poly1305.NonceSize || e != nil {
			panic("invalid nonce length or unexpected error")
		}

		// write cipher
		bytesWritten, err := cipherWriter.Write(cipher)
		if bytesWritten < bytesRead || err != nil {
			return fmt.Errorf("failed to write (%d): %v", bytesWritten, err)
		}
	}
	return nil
}

func (key *Key) Hex() string {
	if key == nil {
		return "nil"
	}
	return hex.EncodeToString(key.bytes[:])
}
