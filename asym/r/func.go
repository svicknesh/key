package r

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"

	"github.com/svicknesh/key/v2/shared"
)

// Generate - generates a new RSA public/private key
func Generate(kt shared.KeyType) (k *K, err error) {
	k = new(K)

	switch kt {
	case shared.RSA2048:
		k.priv, err = rsa.GenerateKey(rand.Reader, 2048)
	case shared.RSA4096:
		k.priv, err = rsa.GenerateKey(rand.Reader, 4096)
	case shared.RSA8192:
		k.priv, err = rsa.GenerateKey(rand.Reader, 8192)
	default:
		return nil, fmt.Errorf("rsa-generate: unsupported key type for RSA generation")
	}

	if nil != err {
		return nil, fmt.Errorf("rsa-generate: error generating RSA key -> %w", err)
	}

	k.isPriv = true
	k.kt = kt

	return
}

// New - converts a raw key interface into instance of RSA
func New(rkey interface{}) (k *K, err error) {

	k = new(K)

	var size int
	switch kt := rkey.(type) {
	case *rsa.PrivateKey:
		k.priv = kt
		k.isPriv = true
		size = kt.Size()
	case *rsa.PublicKey:
		k.pub = kt
		k.isPub = true
		size = kt.Size()
	default:
		return nil, fmt.Errorf("rsa-new: does not support creating instance of %T", kt)
	}

	switch size {
	case 256: // 2048 bit RSA key
		k.kt = shared.RSA2048
	case 512: // 4096 bit RSA key
		k.kt = shared.RSA4096
	case 1024: // 8192 bit RSA key
		k.kt = shared.RSA8192
	}

	return k, nil
}
