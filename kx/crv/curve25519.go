package crv

import (
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/svicknesh/key/v2/shared"
	"golang.org/x/crypto/curve25519"
)

const (
	// TypeCrvPriv - identifier to be appended at the start of Bytes() to distinguish it as a Curve25519 private key
	TypeCrvPriv uint8 = 201

	// TypeCrvPub - identifier to be appended at the start of Bytes() to distinguish it as a Curve25519 public key
	TypeCrvPub uint8 = 202
)

type KX struct {
	priv, pub     [32]byte
	isPriv, isPub bool
}

// Bytes - returns bytes of the key
func (kx *KX) Bytes() (bytes []byte, err error) {

	bytes = make([]byte, 1)

	if kx.isPriv {
		bytes[0] = TypeCrvPriv
		bytes = append(bytes, kx.priv[:]...)
	} else if kx.isPub {
		bytes[0] = TypeCrvPub
		bytes = append(bytes, kx.pub[:]...)
	} else {
		return nil, fmt.Errorf("curve25519-bytes: neither public nor private key found")
	}

	return
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
	curve25519.ScalarBaseMult(&pub.pub, &kx.priv)
	pub.isPub = true

	return pub
}

// PublicKeyInstance - returns actual instance of public key of type
func (kx *KX) PublicKeyInstance() (pubkey []byte) {
	if kx.isPub {
		return kx.pub[:]
	} else if kx.isPriv {
		return kx.PublicKey().PublicKeyInstance()
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
	return shared.CURVE25519
}

// PublicKey - returns instance of public key of type Key Exchange
func (kx *KX) SharedSecret(kxPub2 shared.KeyExchange) (sharedsecret []byte, err error) {
	if !kx.isPriv {
		return nil, errors.New("curve25519-publickey: no private key exists to generate shared secret")
	}

	if !kxPub2.IsPublicKey() {
		return nil, errors.New("curve25519-publickey: no public key exists in paramameter to generate shared secret")
	}

	return curve25519.X25519(kx.priv[:], kxPub2.PublicKeyInstance())

}
