package key

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"fmt"
)

type KeyType uint8 // new type to define key types to be generated

const (

	// RSA2048 - generate an RSA 2048 bit key
	RSA2048 KeyType = iota

	// RSA4096 - generate an RSA 4096 bit key
	RSA4096

	// ECDSA256 - generate an ECDSA 256 bit key
	ECDSA256

	// ECDSA384 - generate an ECDSA 384 bit key
	ECDSA384

	// ECDSA521 - generate an ECDSA 512 bit key
	ECDSA521
)

// Generate - generates a new key
func Generate(keytype KeyType) (j *JWK, err error) {

	var key interface{}

	switch keytype {
	case ECDSA256:
		key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	case ECDSA384:
		key, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)

	case ECDSA521:
		key, err = ecdsa.GenerateKey(elliptic.P521(), rand.Reader)

	case RSA2048:
		key, err = rsa.GenerateKey(rand.Reader, 2048)

	case RSA4096:
		key, err = rsa.GenerateKey(rand.Reader, 4096)

	default:
		err = errors.New("unsupported key type given for generation")
	}

	if nil != err {
		return nil, fmt.Errorf("generate: %w", err)
	}

	return New(key)
}
