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
