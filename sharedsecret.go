package key

import (
	"crypto/rand"
	"fmt"

	"golang.org/x/crypto/curve25519"
)

func NewKX() (privateKey, publicKey [32]byte, err error) {

	priv := make([]byte, 32)
	_, err = rand.Read(priv)
	if nil != err {
		err = fmt.Errorf("newkx: %v", err.Error())
		return
	}

	privateKey = [32]byte(priv)
	priv = nil

	curve25519.ScalarBaseMult(&publicKey, &privateKey)

	return
}

func SharedSecret(ownPrivateKey, targetPubKey [32]byte) (sharedSecret []byte, err error) {
	return curve25519.X25519(ownPrivateKey[:], targetPubKey[:])
}
