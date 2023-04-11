package ecdhc

import (
	"crypto/ecdh"
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/svicknesh/key/v2/shared"
)

const (
	// TypeECDHPriv256 - identifier to be appended at the start of Bytes() to distinguish it as a ECDH-256 private key
	TypeECDHPriv256 uint8 = 211

	// TypeECDHPub256 - identifier to be appended at the start of Bytes() to distinguish it as a ECDH-256 public key
	TypeECDHPub256 uint8 = 212

	// TypeECDHPriv384 - identifier to be appended at the start of Bytes() to distinguish it as a ECDH-384 private key
	TypeECDHPriv384 uint8 = 213

	// TypeECDHPub384 - identifier to be appended at the start of Bytes() to distinguish it as a ECDH-384 public key
	TypeECDHPub384 uint8 = 214

	// TypeECDHPriv521 - identifier to be appended at the start of Bytes() to distinguish it as a ECDH-521 private key
	TypeECDHPriv521 uint8 = 215

	// TypeECDHPub521 - identifier to be appended at the start of Bytes() to distinguish it as a ECDH-521 public key
	TypeECDHPub521 uint8 = 216
)

type KX struct {
	kxt           shared.KeyXType
	priv          *ecdh.PrivateKey
	pub           *ecdh.PublicKey
	isPriv, isPub bool
}

// Bytes - returns JSON encoded bytes of the key
func (kx *KX) Bytes() (bytes []byte, err error) {

	bytes = make([]byte, 1)

	if kx.isPriv {

		switch kx.kxt {
		case shared.ECDH256:
			bytes[0] = TypeECDHPriv256
		case shared.ECDH384:
			bytes[0] = TypeECDHPriv384
		case shared.ECDH521:
			bytes[0] = TypeECDHPriv521
		}

		bytes = append(bytes, kx.priv.Bytes()...)

	} else if kx.isPub {

		switch kx.kxt {
		case shared.ECDH256:
			bytes[0] = TypeECDHPub256
		case shared.ECDH384:
			bytes[0] = TypeECDHPub384
		case shared.ECDH521:
			bytes[0] = TypeECDHPub521
		}

		bytes = append(bytes, kx.pub.Bytes()...)
	} else {
		return nil, fmt.Errorf("curve25519-bytes: neither public nor private key found")
	}

	return // there is nothing to return for ECDH
}

// String - returns JSON encoded string of the key
func (kx *KX) String() (str string) {
	kb, _ := kx.Bytes()
	return base64.URLEncoding.EncodeToString(kb)
}

// PublicKey - returns instance of public key of type Key Exchange
func (kx *KX) PublicKey() (kxPub shared.KeyExchange) {
	if !kx.isPriv {
		return new(KX)
	}

	pub := new(KX)
	pub.pub = kx.priv.PublicKey()
	pub.isPub = true
	pub.kxt = kx.kxt

	return pub
}

// PublicKeyInstance - returns actual instance of public key of type
func (kx *KX) PublicKeyInstance() (pubkey []byte) {
	if kx.isPriv {
		return kx.priv.PublicKey().Bytes()
	} else if kx.isPub {
		return kx.pub.Bytes()
	}

	return // shouldn't reach this code, it means neither public nor private key exists
}

// IsPrivateKey - returns if K is a private key instance
func (kx *KX) IsPrivateKey() (p bool) {
	return kx.isPriv
}

// IsPublicKey - returns if K is a public key instance
func (kx *KX) IsPublicKey() (p bool) {
	return kx.isPub
}

// KeyType - returns key type
func (kx *KX) KeyType() (kxt shared.KeyXType) {
	return kx.kxt
}

// PublicKey - returns instance of public key of type Key Exchange
func (kx *KX) SharedSecret(kxPub shared.KeyExchange) (sharedsecret []byte, err error) {
	if !kx.isPriv {
		return nil, errors.New("ecdh-sharedsecret: no private key exists for shared secret generation")
	}

	if !kxPub.IsPublicKey() {
		return nil, errors.New("ecdh-sharedsecret: no public key exists in paramameter for shared secret generation")
	}

	pub := new(ecdh.PublicKey)
	switch kxPub.KeyType() {
	case shared.ECDH256:
		pub, err = ecdh.P256().NewPublicKey(kxPub.PublicKeyInstance())
	case shared.ECDH384:
		pub, err = ecdh.P384().NewPublicKey(kxPub.PublicKeyInstance())
	case shared.ECDH521:
		pub, err = ecdh.P521().NewPublicKey(kxPub.PublicKeyInstance())
	default:
		err = errors.New("unsupported ECDH key type for shared secret generation")
	}

	if nil != err {
		return nil, fmt.Errorf("ecdh-sharedsecret: %w", err)
	}

	return kx.priv.ECDH(pub)

}
