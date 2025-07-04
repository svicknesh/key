package r

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/svicknesh/key/v2/shared"
)

type K struct {
	kt            shared.KeyType
	priv          *rsa.PrivateKey
	pub           *rsa.PublicKey
	isPriv, isPub bool
	kid           string
}

// Bytes - returns JSON encoded bytes of the key
func (k *K) Bytes() (bytes []byte, err error) {

	var in any
	if k.isPriv {
		in = k.priv
	} else if k.isPub {
		in = k.pub
	} else {
		return nil, fmt.Errorf("rsa-bytes: neither public nor private key found")
	}

	jk, err := jwk.Import(in)
	if nil != err {
		return nil, fmt.Errorf("rsa-bytes: error importing raw key -> %w", err)
	}

	if len(k.kid) == 0 {
		// assign a default key ID by generating its hash
		err = jwk.AssignKeyID(jk)
		if nil != err {
			return nil, fmt.Errorf("rsa-bytes: error generating key id -> %w", err)
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
	if k.isPub {
		return k, nil // if this is already a public key, return it immediately
	} else if !k.isPriv {
		return nil, errors.New("rsa-publickey: no private key exists to extract public key")
	}

	return New(k.priv.Public())
}

// PrivateKeyInstance - returns actual instance of private key of type
func (k *K) PrivateKeyInstance() (privkey any) {
	if !k.isPriv {
		return nil
	}

	return k.priv
}

// PublicKeyInstance - returns actual instance of public key of type
func (k *K) PublicKeyInstance() (pubkey any) {
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

// Sign - signs the given hashed data using the RSA private key (using RSA PSS)
func (k *K) Sign(hashed []byte) (signed []byte, err error) {

	if !k.isPriv {
		return nil, fmt.Errorf("rsa-sign: private key does not exist for signing data")
	}

	//signed, err = rsa.SignPKCS1v15(rand.Reader, k.priv, crypto.SHA256, hashed)
	signed, err = rsa.SignPSS(rand.Reader, k.priv, crypto.SHA256, hashed, nil)
	if nil != err {
		err = fmt.Errorf("rsa-verify: RSA signature generation failed -> %w", err)
	}

	return
}

// Verify - verifies the signed data of the given hashed data using the RSA public key (using RSA PSS)
func (k *K) Verify(signed []byte, hashed []byte) (ok bool) {

	if !k.isPub {
		return
	}

	//err = rsa.VerifyPKCS1v15(k.pub, crypto.SHA256, hashed, signed)
	err := rsa.VerifyPSS(k.pub, crypto.SHA256, hashed, signed, nil)
	if nil == err {
		ok = true // if there are no errors from VerifyPSS, all is good with the verification
	}

	return
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
