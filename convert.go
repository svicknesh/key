package key

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"

	"github.com/lestrrat-go/jwx/jwk"
)

// ParsePEM - parses PEM encoded bytes into a key
func ParsePEM(pemBytes, password []byte) (j *JWK, err error) {

	var key interface{}
	p, _ := pem.Decode(pemBytes) // for private key there should be no next

	var keyBytes []byte
	if x509.IsEncryptedPEMBlock(p) {
		keyBytes, err = x509.DecryptPEMBlock(p, password)
		if nil != err {
			return nil, fmt.Errorf("parsePEM: %s", err)
		}
	} else {
		keyBytes = p.Bytes
	}

	// identify key type to do proper decoding
	switch p.Type {

	case "EC PRIVATE KEY":
		key, err = x509.ParseECPrivateKey(keyBytes)

	case "RSA PRIVATE KEY", "PRIVATE KEY":
		key, err = x509.ParsePKCS8PrivateKey(keyBytes) // try to parse #PKCS#8 encoding
		if nil != err {
			key, err = x509.ParsePKCS1PrivateKey(keyBytes) // try to parse as PKCS#1
		}

	case "RSA PUBLIC KEY", "EC PUBLIC KEY", "PUBLIC KEY":
		key, err = x509.ParsePKIXPublicKey(keyBytes) // try to parse #PKCS#8 encoding
		if nil != err {
			key, err = x509.ParsePKCS1PublicKey(keyBytes) // try to parse as PKCS#1

		}

	}

	// if an error is found, return with indication where it happened
	if nil != err {
		return nil, fmt.Errorf("parsePEM: %s", err)
	}

	return New(key)
}

// ParseJWK - parses JWK JSON encoded bytes into a key
func ParseJWK(jsonBytes []byte) (j *JWK, err error) {

	var key interface{}

	jKey, err := jwk.ParseKey(jsonBytes)
	if err != nil {
		return nil, fmt.Errorf("parseJWK: %w", err)
	}

	if err = jKey.Raw(&key); err != nil {
		return nil, fmt.Errorf("parseJWK: %w", err)
	}

	return New(key)
}
