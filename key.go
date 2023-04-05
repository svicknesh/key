package key

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"

	"github.com/lestrrat-go/jwx/jwk"
)

// JWK - RSA & EC keys is in JWK format
type JWK struct {
	Kty string `yaml:"kty,omitempty" json:"kty,omitempty"`
	Crv string `yaml:"crv,omitempty" json:"crv,omitempty"`
	N   string `yaml:"n,omitempty" json:"n,omitempty"`
	E   string `yaml:"e,omitempty" json:"e,omitempty"`
	G   string `yaml:"g,omitempty" json:"g,omitempty"`
	P   string `yaml:"p,omitempty" json:"p,omitempty"`
	Q   string `yaml:"q,omitempty" json:"q,omitempty"`
	X   string `yaml:"x,omitempty" json:"x,omitempty"`
	Y   string `yaml:"y,omitempty" json:"y,omitempty"`
	D   string `yaml:"d,omitempty" json:"d,omitempty"`
	DP  string `yaml:"dp,omitempty" json:"dp,omitempty"`
	DQ  string `yaml:"dq,omitempty" json:"dq,omitempty"`
	QI  string `yaml:"qi,omitempty" json:"qi,omitempty"`
	Kid string `yaml:"kid,omitempty" json:"kid,omitempty"`

	// helper variables useful in other parts of this library
	privkey      interface{}
	pubKey       interface{}
	isPrivateKey bool
	isPublicKey  bool
}

// ecdsasig - ecdsa encoding using ASN.1
type ecdsasig struct {
	R, S *big.Int
}

// New - creates a new instance of JWK from a given public or private key
func New(key interface{}) (j *JWK, err error) {

	j = new(JWK)

	set, err := jwk.New(key)
	if nil != err {
		return nil, fmt.Errorf("new init: %w", err)
	}

	jwkBytes, err := json.Marshal(set)
	if nil != err {
		return nil, fmt.Errorf("new marshal: %w", err)
	}

	json.Unmarshal(jwkBytes, j) // if the marshal worked, there won't be an error here

	// we do json marshal followed by unmarshal so we can create our own instance of JWK that fits the structure we are looking for

	switch k := key.(type) {
	case *ecdsa.PrivateKey:
		j.privkey = k

		priv := key.(*ecdsa.PrivateKey)
		j.pubKey = &priv.PublicKey

		j.isPrivateKey = true
		j.isPublicKey = true

	case ecdsa.PrivateKey:

		priv := key.(ecdsa.PrivateKey)

		j.privkey = &priv
		j.pubKey = &priv.PublicKey

		j.isPrivateKey = true
		j.isPublicKey = true

	case *rsa.PrivateKey:
		j.privkey = k

		priv := key.(*rsa.PrivateKey)
		j.pubKey = &priv.PublicKey

		j.isPrivateKey = true
		j.isPublicKey = true

	case rsa.PrivateKey:

		priv := key.(rsa.PrivateKey)
		j.privkey = &priv
		j.pubKey = &priv.PublicKey

		j.isPrivateKey = true
		j.isPublicKey = true

	case *ecdsa.PublicKey, *rsa.PublicKey:
		j.pubKey = k
		j.isPublicKey = true

	case ecdsa.PublicKey: // for verification, we need *ecdsa.PublicKey
		pub := key.(ecdsa.PublicKey)
		j.pubKey = &pub

		j.isPublicKey = true

	case rsa.PublicKey: // for verification, we need *rsa.PublicKey
		pub := key.(rsa.PublicKey)
		j.pubKey = &pub

		j.isPublicKey = true

	}

	return
}

// SetKeyID - set a key id for a given key
func (j *JWK) SetKeyID(kid string) {
	j.Kid = kid
}

// Sign - signs the given data using the private key in this JWK instance
func (j *JWK) Sign(hashed []byte) (signed []byte, err error) {

	if !j.isPrivateKey {
		return nil, fmt.Errorf("sign: no private key exist for signing data")
	}

	switch j.Kty {
	case "EC":

		var encode ecdsasig
		encode.R, encode.S, err = ecdsa.Sign(rand.Reader, j.privkey.(*ecdsa.PrivateKey), hashed)
		if nil != err {
			return nil, fmt.Errorf("sign: %w", err)
		}

		signed, err = asn1.Marshal(encode)

	case "RSA":
		signed, err = rsa.SignPKCS1v15(rand.Reader, j.privkey.(*rsa.PrivateKey), crypto.SHA256, hashed)
	}

	if nil != err {
		return nil, fmt.Errorf("sign: %w", err)
	}

	return
}

// Verify - verifies the given data using the public key in this JWK instance
func (j *JWK) Verify(signed, hashed []byte) (err error) {

	if !j.isPublicKey {
		return fmt.Errorf("verify: no public key exist for verifying data")
	}

	switch j.Kty {
	case "EC":

		// we found the ECDSA public key
		var decode ecdsasig

		_, err = asn1.Unmarshal(signed, &decode)
		if nil != err {
			return fmt.Errorf("verify: %w", err)
		}

		if !ecdsa.Verify(j.pubKey.(*ecdsa.PublicKey), hashed, decode.R, decode.S) {
			err = fmt.Errorf("verify: ECDSA signature verification failed")
		}

	case "RSA":
		err = rsa.VerifyPKCS1v15(j.pubKey.(*rsa.PublicKey), crypto.SHA256, hashed, signed)
		if nil != err {
			err = fmt.Errorf("verify: %w", err)
		}
	}

	return
}

// Key - returns an `RSA` or `ECDSA` instance of the Key, this will return private key first and if it doesn't exist, only then return the public key
func (j *JWK) Key() (key interface{}) {

	if j.isPrivateKey {
		return j.privkey
	} else {
		return j.pubKey
	}

}

// PublicKey - returns a JWK instance of `PublicKey`
func (j *JWK) PublicKey() (p *JWK) {
	p, _ = New(j.pubKey) // create a new instance of the JWK publickey
	return p
}

// Bytes - returns a JSON encoded byte of the key
func (j *JWK) Bytes() (bytes []byte) {
	bytes, _ = json.Marshal(j)
	return
}

// String - returns a JSON encoded string of the key
func (j *JWK) String() (str string) {
	return string(j.Bytes())
}

// PEM - returns a PEM encoded string of the key
func (j *JWK) PEM() (pemBytes []byte) {

	var pemType string
	var keyBytes []byte

	if j.isPrivateKey {

		switch j.Kty {
		case "EC":
			pemType = "EC PRIVATE KEY"
			keyBytes, _ = x509.MarshalECPrivateKey(j.privkey.(*ecdsa.PrivateKey))

		case "RSA":
			pemType = "PRIVATE KEY"
			keyBytes, _ = x509.MarshalPKCS8PrivateKey(j.privkey.(*rsa.PrivateKey))
		}

	} else {
		// if it isn't a private key, it's a public key
		pemType = "PUBLIC KEY"
		keyBytes, _ = x509.MarshalPKIXPublicKey(j.pubKey)
	}

	return pem.EncodeToMemory(&pem.Block{
		Type:  pemType,
		Bytes: keyBytes,
	})
}
