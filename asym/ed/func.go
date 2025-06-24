package ed

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
)

// Generate - generates a new ED255 public/private key
func Generate() (k *K, err error) {
	k = new(K)

	_, k.priv, err = ed25519.GenerateKey(rand.Reader)
	if nil != err {
		return nil, fmt.Errorf("ed25519-generate: error generating ED25519 key -> %w", err)
	}

	k.isPriv = true

	return
}

// New - converts a raw key interface into instance of ED25519
func New(rkey any) (k *K, err error) {

	k = new(K)

	switch kt := rkey.(type) {
	case ed25519.PrivateKey:
		k.priv = kt
		k.isPriv = true
	case ed25519.PublicKey:
		k.pub = kt
		k.isPub = true
	default:
		return nil, fmt.Errorf("ed25519-new: does not support creating instance of %T", kt)
	}

	return k, nil
}
