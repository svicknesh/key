package key

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"testing"

	"github.com/lestrrat-go/jwx/jwk"
)

func TestGen(t *testing.T) {

	privJWK, err := Generate(ECDSA256)
	if nil != err {
		fmt.Println(err)
		os.Exit(1)
	}
	fmt.Println(privJWK.String())

	pubJWK, err := ParseJWK(privJWK.PublicKey().Bytes())
	if nil != err {
		fmt.Println(err)
		os.Exit(1)
	}
	fmt.Println(pubJWK.String())

	fmt.Println(string(privJWK.PEM()))

	j, err := ParsePEM(privJWK.PEM(), nil)
	if nil != err {
		fmt.Println(err)
		os.Exit(1)
	}
	fmt.Println(j.String())

}

func TestKey(t *testing.T) {

	privJWK, err := Generate(ECDSA256)
	if nil != err {
		fmt.Println(err)
		os.Exit(1)
	}
	fmt.Println(privJWK.String())

	pubJWK, err := ParseJWK(privJWK.PublicKey().Bytes())
	if nil != err {
		fmt.Println(err)
		os.Exit(1)
	}

	hashed := sha256.Sum256([]byte("hello world"))
	signed, err := privJWK.Sign(hashed[:])
	if nil != err {
		fmt.Println(err)
		os.Exit(1)
	}
	fmt.Println(hex.EncodeToString(signed))

	err = pubJWK.Verify(signed, hashed[:])
	if nil != err {
		fmt.Println(err)
		os.Exit(1)
	}

	fmt.Println("\nsignature matches, success")

}

func TestPEM(t *testing.T) {

	k, err := Generate(ECDSA256)
	if nil != err {
		fmt.Println(err)
		os.Exit(1)
	}

	privJWK, err := ParsePEM(k.PEM(), nil)
	if nil != err {
		fmt.Println(err)
		os.Exit(1)
	}

	pubJWK, err := ParsePEM(k.PublicKey().PEM(), nil)
	if nil != err {
		fmt.Println(err)
		os.Exit(1)
	}

	hashed := sha256.Sum256([]byte("hello world"))
	signed, err := privJWK.Sign(hashed[:])
	if nil != err {
		fmt.Println(err)
		os.Exit(1)
	}
	fmt.Println(hex.EncodeToString(signed))

	err = pubJWK.Verify(signed, hashed[:])
	if nil != err {
		fmt.Println(err)
		os.Exit(1)
	}

	fmt.Println("\nsignature matches, success")

}

func TestJWK(t *testing.T) {

	// EC key
	privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	publicKey := privateKey.PublicKey

	jwkPriv, err := jwk.New(privateKey)
	if nil != err {
		fmt.Println(err)
		os.Exit(1)
	}

	jwkPub, err := jwk.New(publicKey)
	if nil != err {
		fmt.Println(err)
		os.Exit(1)
	}

	jwkPrivBytes, _ := json.Marshal(jwkPriv)
	fmt.Println(string(jwkPrivBytes))

	jwkPubBytes, _ := json.Marshal(jwkPub)
	fmt.Println(string(jwkPubBytes))

	privJWK, err := ParseJWK(jwkPrivBytes)
	if nil != err {
		fmt.Println(err)
		os.Exit(1)
	}

	pubJWK, err := ParseJWK(jwkPubBytes)
	if nil != err {
		fmt.Println(err)
		os.Exit(1)
	}

	hashed := sha256.Sum256([]byte("hello world"))
	signed, err := privJWK.Sign(hashed[:])
	if nil != err {
		fmt.Println(err)
		os.Exit(1)
	}
	fmt.Println(hex.EncodeToString(signed))

	err = pubJWK.Verify(signed, hashed[:])
	if nil != err {
		fmt.Println(err)
		os.Exit(1)
	}

	fmt.Println("\nsignature matches, success")

}
