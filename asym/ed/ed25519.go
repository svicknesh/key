package ed

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/svicknesh/key/v2/shared"
)

type K struct {
	priv          ed25519.PrivateKey
	pub           ed25519.PublicKey
	isPriv, isPub bool
	kid           string
}

// Bytes - returns JSON encoded bytes of the key
func (k *K) Bytes() (bytes []byte, err error) {

	var in interface{}
	if k.isPriv {
		in = k.priv
	} else if k.isPub {
		in = k.pub
	} else {
		return nil, fmt.Errorf("ed25519-bytes: neither public nor private key found")
	}

	jk, err := jwk.Import(in)
	if nil != err {
		return nil, fmt.Errorf("ed25519-bytes: error importing raw key -> %w", err)
	}

	if len(k.kid) == 0 {
		// assign a default key ID by generating its hash
		err = jwk.AssignKeyID(jk)
		if nil != err {
			return nil, fmt.Errorf("ed25519-bytes: error generating key id -> %w", err)
		}
	} else {
		jk.Set(jwk.KeyIDKey, k.kid)
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
		return nil, errors.New("ed25519-publickey: no private key exists to extract public key")
	}

	return New(k.priv.Public())
}

// PrivateKeyInstance - returns actual instance of private key of type
func (k *K) PrivateKeyInstance() (privkey interface{}) {
	if !k.isPriv {
		//return nil, errors.New("ed25519-privatekeyinstance: no private key exists")
		return nil
	}

	return k.priv
}

// PublicKeyInstance - returns actual instance of public key of type
func (k *K) PublicKeyInstance() (pubkey interface{}) {
	if k.isPub {
		return k.pub
	} else if k.isPriv {
		return k.priv.Public()
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
	return shared.ED25519
}

// Sign - signs the given hashed data using the ED25519 private key
func (k *K) Sign(hashed []byte) (signed []byte, err error) {

	if !k.isPriv {
		return nil, fmt.Errorf("ed25519-sign: private key does not exist for signing data")
	}

	signed = ed25519.Sign(k.priv, hashed)

	return
}

// Verify - verifies the signed data of the given hashed data using the ED25519 public key
func (k *K) Verify(signed []byte, hashed []byte) (ok bool) {
	if !k.isPub {
		return
	}

	return ed25519.Verify(k.pub, hashed, signed)
}

// MarshalJSON - marshals this Key into a JSON
func (k K) MarshalJSON() (bytes []byte, err error) {
	return k.Bytes()
}

// SetKeyID - sets a custom key ID `kid` for the key
func (k *K) SetKeyID(kid string) (err error) {
	k.kid = kid
	return
}

// GetKeyID - returns the key ID `kid` from the key
func (k *K) GetKeyID() (kid string) {
	return k.kid
}
