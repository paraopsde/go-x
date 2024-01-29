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
	for {
		// read chunk size and nonce
		buf := make([]byte, 8)
		n, err := io.ReadFull(cipherReader, buf)
		if err != nil {
			return fmt.Errorf("failed to read header bytes: %w", err)
		}
		if n != 8 {
			return fmt.Errorf("failed to read header bytes (%d): short read", n)
		}
		thisChunkSize := binary.BigEndian.Uint64(buf)
		if thisChunkSize == 0 {
			// terminating zero found
			break
		}
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
	n, err := key.ChachaSealFromReader(bytes.NewReader(plain), cipher)
	if err != nil {
		return nil, fmt.Errorf("failed to seal: %v", err)
	}
	if n != int64(cipher.Len()) {
		return nil, fmt.Errorf("failed to seal: length mismatch (%d/%d)", n, cipher.Len())
	}
	return cipher.Bytes(), nil
}

// ChachaOpen is a variant using `ChachaOpenFromReader` that takes a slice
// of bytes instead of an io.Reader
func (key *Key) ChachaOpen(cipher []byte) ([]byte, error) {
	plain := bytes.NewBuffer(make([]byte, 0, len(cipher)))
	err := key.ChachaOpenFromReader(bytes.NewReader(cipher), plain)
	if err != nil {
		return nil, fmt.Errorf("failed to open: %v", err)
	}
	return plain.Bytes(), nil
}

// ChachaSealFromReader reads plain text from an io.Reader and writes
// authenticated and encrypted data into an io.Writer.
// The sealing is done in chunks of `chunkSize` bytes. Every such chunk
// is preceded by 64bit big endian encoded size of the cipher text and
// a nonce used for that chunk.
// Following the final chunk a 64bit zero is written to denote the end
// of the cipher text.
func (key *Key) ChachaSealFromReader(plainReader io.Reader, cipherWriter io.Writer) (int64, error) {
	var (
		primeNonce   = make([]byte, chacha20poly1305.NonceSize)
		chunk        = make([]byte, chunkSize)
		nonceInc     uint64
		bytesWritten int64
	)
	crand.Read(primeNonce[:])

	for eof := false; !eof; {
		// read plain
		bytesRead, err := io.ReadFull(plainReader, chunk)
		if err != nil {
			if err != io.EOF && err != io.ErrUnexpectedEOF {
				return 0, fmt.Errorf("failed to read %d bytes: %w", chunkSize, err)
			} else {
				eof = true
			}
		}

		if bytesRead == 0 {
			break
		}

		// seal chunk
		nonce := CountedNonce(primeNonce, nonceInc)
		nonceInc++
		cipher := key.aead.Seal(nil, nonce, chunk[:bytesRead], nil)

		// write nonce and chunk size (of cipher)
		buf := make([]byte, 8)
		binary.BigEndian.PutUint64(buf, uint64(len(cipher)))
		n, e := cipherWriter.Write(buf)
		if e != nil {
			return 0, fmt.Errorf("failed to write chunk header: %w", e)
		}
		if n != 8 {
			return 0, fmt.Errorf("failed to write chunk header: short write (%d)", n)
		}
		bytesWritten += int64(n)

		n, e = cipherWriter.Write(nonce)
		if e != nil {
			return 0, fmt.Errorf("failed to write chunk nonce: %w", e)
		}
		if n != chacha20poly1305.NonceSize {
			return 0, fmt.Errorf("failed to write chunk nonce: short write (%d)", n)
		}
		bytesWritten += int64(n)

		// write cipher
		n, err = cipherWriter.Write(cipher)
		if n < bytesRead || err != nil {
			return 0, fmt.Errorf("failed to write (%d): %v", n, err)
		}
		bytesWritten += int64(n)
	}

	// write a terminating zero
	zero := make([]byte, 8)
	n, e := cipherWriter.Write(zero)
	if e != nil {
		return 0, fmt.Errorf("failed to write terminating chunk zero: %w", e)
	}
	if n != 8 {
		return 0, fmt.Errorf("failed to write terminating chunk zero: short write (%d)", n)
	}

	bytesWritten += int64(n)
	return bytesWritten, nil
}

func (key *Key) Hex() string {
	if key == nil {
		return "nil"
	}
	return hex.EncodeToString(key.bytes[:])
}
