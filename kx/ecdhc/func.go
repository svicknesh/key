package ecdhc

import (
	"crypto/ecdh"
	"crypto/rand"
	"fmt"

	"github.com/svicknesh/key/v2/shared"
)

// Generate - generates a new EC Diffie Hellman public/private key from existing ECDSA keys
func Generate(kxt shared.KeyXType) (kx *KX, err error) {
	kx = new(KX)

	switch kxt {
	case shared.ECDH256:
		kx.priv, err = ecdh.P256().GenerateKey(rand.Reader)
	case shared.ECDH384:
		kx.priv, err = ecdh.P384().GenerateKey(rand.Reader)
	case shared.ECDH521:
		kx.priv, err = ecdh.P521().GenerateKey(rand.Reader)
	default:
		return nil, fmt.Errorf("ecdh-generate: unsupported key type for ECDH generation")
	}

	if nil != err {
		return nil, fmt.Errorf("ecdh-generate: error generating ECDH key -> %w", err)
	}

	kx.kxt = kxt
	kx.isPriv = true

	return
}

// New - returns new instnace of key exchange from given bytes
func New(kxBytes []byte) (kx *KX, err error) {

	kx = new(KX)

	identifier := kxBytes[0] // first byte indicates the type of key exchange
	kxB := kxBytes[1:]       // the remainder is the actual key exchange bytes

	switch identifier {
	case TypeECDHPriv256:
		kx.kxt = shared.ECDH256
		kx.priv, err = ecdh.P256().NewPrivateKey(kxB)
		kx.isPriv = true

	case TypeECDHPub256:
		kx.kxt = shared.ECDH256
		kx.pub, err = ecdh.P256().NewPublicKey(kxB)
		kx.isPub = true

	case TypeECDHPriv384:
		kx.kxt = shared.ECDH384
		kx.priv, err = ecdh.P384().NewPrivateKey(kxB)
		kx.isPriv = true

	case TypeECDHPub384:
		kx.kxt = shared.ECDH384
		kx.pub, err = ecdh.P384().NewPublicKey(kxB)
		kx.isPub = true

	case TypeECDHPriv521:
		kx.kxt = shared.ECDH521
		kx.priv, err = ecdh.P521().NewPrivateKey(kxB)
		kx.isPriv = true

	case TypeECDHPub521:
		kx.kxt = shared.ECDH521
		kx.pub, err = ecdh.P521().NewPublicKey(kxB)
		kx.isPub = true

	}

	return
}
