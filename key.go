package key

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/svicknesh/key/v2/asym/ec"
	"github.com/svicknesh/key/v2/asym/ed"
	"github.com/svicknesh/key/v2/asym/r"
	"github.com/svicknesh/key/v2/kx/crv"
	"github.com/svicknesh/key/v2/kx/ecdhc"
	"github.com/svicknesh/key/v2/shared"
)

// Key - alias of `shared.Key`
type Key = shared.Key // create an alias so users don't need to understand the layout of the library to use this type

// Key - alias of `shared.KeyExchange`
type KeyExchange = shared.KeyExchange

// NewKeyFromBytes - returns new instance of key from given JWK bytes
func NewKeyFromBytes(jwkBytes []byte) (k Key, err error) {

	var rkey interface{}

	err = jwk.ParseRawKey(jwkBytes, &rkey)
	if err != nil {
		return nil, fmt.Errorf("newkeyfrombytes: %w", err)
	}

	switch rkey.(type) {
	case ed25519.PrivateKey, ed25519.PublicKey:
		k, err = ed.New(rkey)
	case *ecdsa.PrivateKey, *ecdsa.PublicKey:
		k, err = ec.New(rkey)
	case *rsa.PrivateKey, *rsa.PublicKey:
		k, err = r.New(rkey)
	}

	if err != nil {
		err = fmt.Errorf("newkeyfrombytes: %w", err)
	}

	return
}

// NewKeyFromStr - returns new instance of key from a given JWK string
func NewKeyFromStr(jwkStr string) (k Key, err error) {
	return NewKeyFromBytes([]byte(jwkStr))
}

// NewFromRawKey - returns new instance of key from given raw key
func NewFromRawKey(rawKey interface{}) (k Key, err error) {

	jk, err := jwk.FromRaw(rawKey)
	if nil != err {
		return nil, fmt.Errorf("newfromrawkey: error converting from raw -> %w", err)
	}

	bytes, err := json.Marshal(jk)
	if nil != err {
		return nil, fmt.Errorf("newfromrawkey: error marshaling -> %w", err)
	}

	k, err = NewKeyFromBytes(bytes)
	if nil != err {
		return nil, fmt.Errorf("newfromrawkey: %w", err)
	}

	return
}

// NewKXFromBytes - returns new instance of key exchange from given bytes
func NewKXFromBytes(kxBytes []byte) (kx KeyExchange, err error) {

	// first byte indicates the type of key exchange
	switch kxBytes[0] {
	case crv.TypeCrvPriv, crv.TypeCrvPub:
		kx, err = crv.New(kxBytes)
	case ecdhc.TypeECDHPriv256, ecdhc.TypeECDHPub256, ecdhc.TypeECDHPriv384, ecdhc.TypeECDHPub384, ecdhc.TypeECDHPriv521, ecdhc.TypeECDHPub521:
		kx, err = ecdhc.New(kxBytes)
	}

	if err != nil {
		err = fmt.Errorf("newkxfrombytes: %w", err)
	}

	return
}

// NewKXFromStr - returns new instance of key exchange from a given string
func NewKXFromStr(kxStr string) (kx KeyExchange, err error) {
	kxBytes, err := base64.URLEncoding.DecodeString(kxStr)
	if err != nil {
		return nil, fmt.Errorf("newkxfromstr: %w", err)
	}

	return NewKXFromBytes(kxBytes)
}

// GetKeyType - returns proper key type given its name
func GetKeyType(ktyName string) (kty shared.KeyType) {

	//ktys := []string{"unknown", ED25519.String(), ECDSA256.String(), ECDSA384.String(), ECDSA521.String(), RSA2048.String(), RSA4096.String(), RSA8192.String()}

	ktys := make(map[string]shared.KeyType)
	ktys[Unknown.String()] = Unknown
	ktys[ED25519.String()] = ED25519
	ktys[ECDSA256.String()] = ECDSA256
	ktys[ECDSA384.String()] = ECDSA384
	ktys[ECDSA521.String()] = ECDSA521
	ktys[RSA2048.String()] = RSA2048
	ktys[RSA4096.String()] = RSA4096
	ktys[RSA8192.String()] = RSA8192

	var ok bool

	kty, ok = ktys[ktyName]
	if !ok {
		kty = Unknown // if an unknown key type is given, return unknown
	}

	return
}

// GetKeyXType - returns proper key exchange type given its name
func GetKeyXType(kxtyName string) (kxty shared.KeyXType) {

	//ktys := []string{"unknown", ED25519.String(), ECDSA256.String(), ECDSA384.String(), ECDSA521.String(), RSA2048.String(), RSA4096.String(), RSA8192.String()}

	kxtys := make(map[string]shared.KeyXType)
	kxtys["unknown"] = shared.KeyXType(0)
	kxtys[CURVE25519.String()] = CURVE25519
	kxtys[ECDH256.String()] = ECDH256
	kxtys[ECDH384.String()] = ECDH384
	kxtys[ECDH521.String()] = ECDH521

	var ok bool

	kxty, ok = kxtys[kxtyName]
	if !ok {
		kxty = shared.KeyXType(0) // if an unknown key exhange type is given, return unknown
	}

	return
}
