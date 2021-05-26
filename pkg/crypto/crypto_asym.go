package crypto

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/kevinburke/nacl"
	"github.com/kevinburke/nacl/box"
	"golang.org/x/crypto/curve25519"
)

const (
	asymKeySize int = nacl.KeySize
)

type AsymKey struct {
	private nacl.Key
	public  nacl.Key
}

var WrongHolder = errors.New("wrong holder")

func NewKeyPair() *AsymKey {
	akey := &AsymKey{private: nacl.NewKey()}
	akey.calcPublic()
	return akey
}

func NewKeyPairFromPrivateHex(hex string) (*AsymKey, error) {
	key, err := nacl.Load(hex)
	if err != nil {
		return nil, fmt.Errorf("failed to load: %v", err)
	}
	akey := &AsymKey{private: key}
	akey.calcPublic()
	return akey, nil
}

func (akey *AsymKey) SealSymKey(symkey *Key) (string, error) {
	sealmap := map[string]string{
		"holder":    akey.PublicHex(),
		"encrypter": akey.PublicHex(),
		"cipher":    base64.StdEncoding.EncodeToString(box.EasySeal(symkey.bytes[:], akey.public, akey.private)),
	}
	sealedJson, err := json.Marshal(sealmap)
	if err != nil {
		return "", fmt.Errorf("failed to json-marshal: %v", err)
	}
	return string(sealedJson), nil
}

func (akey *AsymKey) OpenSymKey(sealed string) (*Key, error) {
	sealmap := map[string]string{}
	if err := json.Unmarshal([]byte(sealed), &sealmap); err != nil {
		return nil, fmt.Errorf("failed to unmarshal: %v", err)
	}
	if sealmap["holder"] != akey.PublicHex() {
		return nil, fmt.Errorf("%w: %s != %s", WrongHolder, sealmap["holder"], akey.PublicHex())
	}

	cipher, err := base64.StdEncoding.DecodeString(sealmap["cipher"])
	if err != nil {
		return nil, fmt.Errorf("failed to base64 decode cipher: %v", err)
	}
	encrypterBytes, err := hex.DecodeString(sealmap["encrypter"])
	if err != nil {
		return nil, fmt.Errorf("failed to decode encrypter: %v", err)
	}
	encrypterPublic := new([asymKeySize]byte)
	copy(encrypterPublic[:], encrypterBytes[:asymKeySize])
	plainBytes, err := box.EasyOpen(cipher, encrypterPublic, akey.private)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt: %v", err)
	}
	return NewKeyFromBytes(plainBytes)
}

func (akey *AsymKey) PrivateHex() string {
	return fmt.Sprintf("%x", *akey.private)
}
func (akey *AsymKey) PublicHex() string {
	return fmt.Sprintf("%x", *akey.public)
}

func (akey *AsymKey) VerboseHex() string {
	return fmt.Sprintf("%x(priv)\n%x(pub)\n", *akey.private, *akey.public)
}

func (akey *AsymKey) calcPublic() {
	akey.public = new([asymKeySize]byte)
	curve25519.ScalarBaseMult(akey.public, akey.private)
}
