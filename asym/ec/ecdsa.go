package ec

import (
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/svicknesh/key/v2/shared"
)

type K struct {
	kt            shared.KeyType
	priv          *ecdsa.PrivateKey
	pub           *ecdsa.PublicKey
	isPriv, isPub bool
}

// Bytes - returns JSON encoded bytes of the key
func (k *K) Bytes() (bytes []byte, err error) {

	var in interface{}
	if k.isPriv {
		in = k.priv
	} else if k.isPub {
		in = k.pub
	} else {
		return nil, fmt.Errorf("ecdsa-bytes: neither public nor private key found")
	}

	jk, err := jwk.FromRaw(in)
	if nil != err {
		return nil, fmt.Errorf("ecdsa-bytes: %w", err)
	}

	return json.Marshal(jk)
}

// String - returns JSON encoded string of the key
func (k *K) String() (str string) {
	kb, _ := k.Bytes()
	return string(kb)
}

// PublicKey - returns instance of public key of type Key extracted from private key
func (k *K) PublicKey() (kPub shared.Key, err error) {
	if !k.isPriv {
		return nil, errors.New("ecdsa-publickey: no private key exists to extract public key")
	}

	return New(k.priv.Public())
}

// PrivateKeyInstance - returns actual instance of private key of type
func (k *K) PrivateKeyInstance() (privkey interface{}) {
	if !k.isPriv {
		return nil
	}

	return k.priv
}

// PublicKeyInstance - returns actual instance of public key of type
func (k *K) PublicKeyInstance() (pubkey interface{}) {
	if k.isPub {
		return k.pub
	} else if k.isPriv {
		return &k.priv.PublicKey
	}

	return // shouldn't reach this code, it means neither public nor private key exists
}

// IsPrivateKey - returns if K is a private key instance
func (k *K) IsPrivateKey() (p bool) {
	return k.isPriv
}

// IsPublicKey - returns if K is a public key instance
func (k *K) IsPublicKey() (p bool) {
	return k.isPub
}

// KeyType - returns key type
func (k *K) KeyType() (kt shared.KeyType) {
	return k.kt
}

// Sign - signs the given hashed data using the ECDSA private key
func (k *K) Sign(hashed []byte) (signed []byte, err error) {

	if !k.isPriv {
		return nil, fmt.Errorf("ecdsa-sign: private key does not exist for signing data")
	}

	signed, err = ecdsa.SignASN1(rand.Reader, k.priv, hashed)
	if nil != err {
		err = fmt.Errorf("ecdsa-verify: ECDSA signature generation failed -> %w", err)
	}

	return
}

// Verify - verifies the signed data of the given hashed data using the ECDSA public key
func (k *K) Verify(signed []byte, hashed []byte) (ok bool) {
	if !k.isPub {
		return
	}

	return ecdsa.VerifyASN1(k.pub, hashed, signed)
}

// MarshalJSON - marshals this Key into a JSON
func (k K) MarshalJSON() (bytes []byte, err error) {
	return k.Bytes()
}
