# Golang Key library

Golang library to 
- sign and verify signature using `ED25519`, `ECDSA` or `RSA` public/private keys.
- creating shared keys using `Curve25519` or `ECDH`.
- Encode keys to JWK (public/private keys ONLY).
- Decode JWK to keys (public/private keys ONLY).

## Key Usage

### Generating keys

Possible key types that can be generated are 
- `ED25519` - ED25519 256 bit
- `ECDSA256` - ECDSA 256 bit
- `ECDSA384` - ECDSA 384 bit
- `ECDSA521` - ECDSA 521 bit
- `RSA2048` - RSA 2048 bit
- `RSA4096` - RSA 4096 bit
- `RSA8192` - RSA 8192 bit

```go
// create a new instance of Key
k, err := GenerateKey(ED25519)
if nil != err {
    fmt.Println(err)
    os.Exit(1)
}
fmt.Println("JWK:", k)
```

### Decode JWK string to key

```go
// create an instance of Key from an existing JWK string
k, err := NewKeyFromStr("{\"crv\":\"Ed25519\",\"d\":\"vUjQ3PaX8iqHA0Q58Wf7mN8h-oMgAE_cFQDfi0Sr2Js\",\"kty\":\"OKP\",\"x\":\"etHd2wg1POjqvQZ3yhiwwU2JRwCtcqzYQIOmp7BnnSo\"}")
if nil != err {
    fmt.Println(err)
    os.Exit(1)
}
fmt.Println("JWK:", k)
```

### Signing hashed data

```go
// assume a key instance already exists from generation or decoding a JWK string

// signing data is done over a hash of existing data
s := sha3.New256()
s.Write([]byte("hello, "))
s.Write([]byte("world"))

h := s.Sum(nil)

// k is an instance of Key
signed, err := k.Sign(h)
if nil != err {
    fmt.Println(err)
    os.Exit(1)
}
fmt.Println(base64.StdEncoding.EncodeToString(signed))
```


### Verifying hashed data

```go
// assume a key instance already exists from generation or decoding a JWK string

if k.Verify(signed, h) {
    fmt.Println("verified data for ED25519")
} else {
    fmt.Println("unable to verify data for ED25519")
}

```

### Complete example

```go
k, err := GenerateKey(ED25519)
if nil != err {
    fmt.Println(err)
    os.Exit(1)
}
fmt.Println("JWK:", k)

kPub, err := k.PublicKey()
if nil != err {
    fmt.Println(err)
    os.Exit(1)
}
//fmt.Println("JWK:", kPub)

k2, err := NewKeyFromStr(kPub.String())
if nil != err {
    fmt.Println(err)
    os.Exit(1)
}
fmt.Println("JWK:", k2)

s := sha3.New256()
s.Write([]byte("hello, "))
s.Write([]byte("world"))

h := s.Sum(nil)

signed, err := k.Sign(h)
if nil != err {
    fmt.Println(err)
    os.Exit(1)
}
fmt.Println(base64.StdEncoding.EncodeToString(signed))

//h = append(h, []byte("abcd")...)
if k2.Verify(signed, h) {
    fmt.Println("verified data for ED25519")
} else {
    fmt.Println("unable to verify data for ED25519")
}
```

## Key Exchange

### Generating keys

Possible key types that can be generated are 
- `CURVE255519` - ED25519Curve25519 256 bit
- `ECDH256` - ECDH 256 bit
- `ECDH384` - ECDH 384 bit
- `ECDH521` - ECDH 521 bit

```go
// create a new instance of Key
a, err := GenerateKeyExchange(CURVE25519)
if nil != err {
    fmt.Println(err)
    os.Exit(1)
}

fmt.Println("A private key:\t", a)
fmt.Println("A public key:\t", a.PublicKey())
```

### Decode key exchange from string

```go
aStr := "ybAlYu1qLcRoiMZKDfuFy8yUTU2TxXRpoYY4xvCjmUfq"

a, err := NewKXFromStr(aStr)
if nil != err {
    fmt.Println(err)
    os.Exit(1)
}
fmt.Println("A private key type: ", a.KeyType())
fmt.Println("A private key:\t", a)
fmt.Println("A public key:\t", a.PublicKey())
```

### Creating shared key

```go
// for a shared key, we would require A's private key and B's public key
// both A and B **MUST** be using the same type of key exchange i.e. CURVE25519 or ECDH*
// assume both have been generated or converted from string

sharedSecretA, err := a.SharedSecret(b.PublicKey())
if nil != err {
    fmt.Println(err)
    os.Exit(1)
}
fmt.Println("A shared secret with B:\t", base64.StdEncoding.EncodeToString(sharedSecretA))

sharedSecretB, err := b.SharedSecret(a.PublicKey())
if nil != err {
    fmt.Println(err)
    os.Exit(1)
}
fmt.Println("B shared secret with A:\t", base64.StdEncoding.EncodeToString(sharedSecretB))

```

### Complete Code

```go
// A
a, err := GenerateKeyExchange(CURVE25519)
if nil != err {
    fmt.Println(err)
    os.Exit(1)
}
//fmt.Println(a)

fmt.Println("A private key:\t", a)
fmt.Println("A public key:\t", a.PublicKey())

// end A

// B
b, err := GenerateKeyExchange(CURVE25519)
if nil != err {
    fmt.Println(err)
    os.Exit(1)
}

fmt.Println("B private key:\t", b)
fmt.Println("B public key:\t", b.PublicKey())

// end B

// generate shared key
sharedSecretA, err := a.SharedSecret(b.PublicKey())
if nil != err {
    fmt.Println(err)
    os.Exit(1)
}
fmt.Println("A shared secret with B:\t", base64.StdEncoding.EncodeToString(sharedSecretA))

sharedSecretB, err := b.SharedSecret(a.PublicKey())
if nil != err {
    fmt.Println(err)
    os.Exit(1)
}
fmt.Println("B shared secret with A:\t", base64.StdEncoding.EncodeToString(sharedSecretB))

// end generate shared key

```