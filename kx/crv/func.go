package crv

import (
	"crypto/rand"
	"fmt"
)

// Generate - generates a new Curve25519 public/private key
func Generate() (kx *KX, err error) {
	kx = new(KX)

	priv := make([]byte, 32)
	_, err = rand.Read(priv)
	if nil != err {
		return nil, fmt.Errorf("curve25519-generate: error generating CURVE25519 -> %w", err)
	}

	copy(kx.priv[:], priv)
	priv = nil
	kx.isPriv = true

	return
}

// New - returns new instnace of key exchange from given bytes
func New(kxBytes []byte) (kx *KX, err error) {

	kx = new(KX)

	identifier := kxBytes[0] // first byte indicates the type of key exchange
	kxB := kxBytes[1:]       // the remainder is the actual key exchange bytes

	switch identifier {
	case TypeCrvPriv:
		kx.priv = [32]byte(kxB)
		kx.isPriv = true
	case TypeCrvPub:
		kx.pub = [32]byte(kxB)
		kx.isPub = true
	}

	return
}
