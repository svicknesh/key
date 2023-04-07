package key

import (
	"crypto/ecdsa"
	"crypto/ed25519"
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

func TestGenED25519(t *testing.T) {

	privJWK, err := Generate(ED25519)
	if nil != err {
		fmt.Println(err)
		os.Exit(1)
	}
	//privJWK.SetKeyID("ed25515-keyid")
	fmt.Println(privJWK.String())

	privJWK, err = ParseJWK(privJWK.Bytes())
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

	hashed := sha256.Sum256([]byte("hello world"))
	signed, err := privJWK.Sign(hashed[:])
	if nil != err {
		fmt.Println(err)
		os.Exit(1)
	}
	fmt.Println("signed " + hex.EncodeToString(signed))
	//signed = append(signed, []byte("1")...)

	err = pubJWK.Verify(signed, hashed[:])
	if nil != err {
		fmt.Println(err)
		os.Exit(1)
	}
	fmt.Println("verified")

	publicKey, privateKey, _ := ed25519.GenerateKey(rand.Reader)

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

	hashed = sha256.Sum256([]byte("hello world"))
	signed, err = privJWK.Sign(hashed[:])
	if nil != err {
		fmt.Println(err)
		os.Exit(1)
	}
	fmt.Println("signed " + hex.EncodeToString(signed))
	//signed = append(signed, []byte("1")...)

	err = pubJWK.Verify(signed, hashed[:])
	if nil != err {
		fmt.Println(err)
		os.Exit(1)
	}
	fmt.Println("verified")

}

func TestKeyExchange(t *testing.T) {

	aPriv, err := NewKX()
	if nil != err {
		fmt.Println(err)
		os.Exit(1)
	}

	aPub := GetKXPubKey(aPriv)

	fmt.Printf("A Private key (a):\t%x\n", aPriv)
	fmt.Printf("A Public key:\t\t%x\n", aPub)

	bPriv, err := NewKX()
	if nil != err {
		fmt.Println(err)
		os.Exit(1)
	}

	bPub := GetKXPubKey(bPriv)

	fmt.Printf("B Private key (b):\t%x\n", bPriv)
	fmt.Printf("B Public key:\t\t%x\n", bPub)

	sharedSecretA, err := SharedSecret(aPriv, bPub)
	if nil != err {
		fmt.Println(err)
		os.Exit(1)
	}

	sharedSecretB, err := SharedSecret(bPriv, aPub)
	if nil != err {
		fmt.Println(err)
		os.Exit(1)
	}

	fmt.Printf("Shared key (A):\t\t%x\n", sharedSecretA)
	fmt.Printf("Shared key (B):\t\t%x\n", sharedSecretB)

}
