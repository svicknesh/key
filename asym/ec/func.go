package ec

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"

	"github.com/svicknesh/key/shared"
)

// Generate - generates a new RSA public/private key
func Generate(kt shared.KeyType) (k *K, err error) {
	k = new(K)

	switch kt {
	case shared.ECDSA256:
		k.priv, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case shared.ECDSA384:
		k.priv, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	case shared.ECDSA521:
		k.priv, err = ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	default:
		return nil, fmt.Errorf("ecdsa-generate: unsupported key type for ECDSA generation")
	}

	if nil != err {
		return nil, fmt.Errorf("ecdsa-generate: error generating ECDSA key -> %w", err)
	}

	k.isPriv = true
	k.kt = kt

	return
}

// New - converts a raw key interface into instance of ECDSA
func New(rkey interface{}) (k *K, err error) {

	k = new(K)

	var crv string

	switch kt := rkey.(type) {
	case *ecdsa.PrivateKey:
		k.priv = kt
		k.isPriv = true
		crv = kt.Curve.Params().Name
	case *ecdsa.PublicKey:
		k.pub = kt
		k.isPub = true
		crv = kt.Curve.Params().Name
	default:
		return nil, fmt.Errorf("ecdsa-new: does not support creating instance of %T", kt)
	}

	switch crv {
	case "P-256":
		k.kt = shared.ECDSA256
	case "P-384":
		k.kt = shared.ECDSA384
	case "P-521":
		k.kt = shared.ECDSA521
	}

	return k, nil
}
