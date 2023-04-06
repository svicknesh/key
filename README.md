# Key

Golang helper library to create JWK keys for signing or verifying hashed data from an `ED25519`, `ECDSA` or `RSA` public/private keys

It also supports creating shared keys using `Curve25519`.

## Usage

### Generating keys

Possible key types that can be generated are 
- `RSA2048` - RSA 2048 bit
- `RSA4096` - RSA 4096 bit
- `ECDSA256` - ECDSA 256 bit
- `ECDSA384` - ECDSA 384 bit
- `ECDSA521` - ECDSA 521 bit
- `ED25519` - ED25519 256 bit

```go
privJWK, err := key.Generate(ECDSA256)
if nil != err {
    fmt.Println(err)
    os.Exit(1)
}
fmt.Println(privJWK.String()) // prints the JWK JSON string of this key

pubJWK := privJWK.PublicKey() // creates an instance of the public key for the generated private key

```


### Signing hashed data

```go
// assume an instance of the private key in JWK instance (`privJWK`) already exists
hashed := sha256.Sum256([]byte("hello world"))
signed, err := privJWK.Sign(hashed[:])
if nil != err {
    fmt.Println(err)
    os.Exit(1)
}
fmt.Println(hex.EncodeToString(signed))

```


### Verifying hashed data

```go
// assume an instance of the public key in JWK instance (`pubJWK`) already exists
err = pubJWK.Verify(signed, hashed[:])
if nil != err {
    fmt.Println(err)
    os.Exit(1)
}

fmt.Println("\nsignature matches, success")

```


### Get key instance

Returns an instance of the public or private key

```go
pemBytes := privJWK.Key()
```


### Generate PEM bytes

```go
pemBytes := privJWK.PEM()

```


### Generate JSON string

```go
jsonStr := privJWK.String()

```


### Reading PEM encoded public/private keys into `JWK` instance

```go
// assume the public/private key in PEM encoded format already exists. password is given in bytes if needed to decrypt the x509 private key PEM
privJWK, err := key.ParsePEM(pemBytes, passwdBytes)
if nil != err {
    fmt.Println(err)
    os.Exit(1)
}

```


### Reading JWK JSON encoded public/private keys into `JWK` instance

```go
// assume the public/private key in JWK JSON string encoded format already exists
privJWK, err := key.ParseJWK(pemBytes)
if nil != err {
    fmt.Println(err)
    os.Exit(1)
}

```

### Creating Shared Secret using `Curve25519`

```go

// create new public, private key for Curve25519 for self
aPriv, aPub, err := NewKX()
if nil != err {
    fmt.Println(err)
    os.Exit(1)
}

fmt.Printf("A Private key (a):\t%x\n", aPriv)
fmt.Printf("A Public key:\t\t%x\n", aPub)

// create new public, private key for Curve25519 for target
bPriv, bPub, err := NewKX()
if nil != err {
    fmt.Println(err)
    os.Exit(1)
}

fmt.Printf("B Private key (b):\t%x\n", bPriv)
fmt.Printf("B Public key:\t\t%x\n", bPub)

// created shared secret for A
sharedSecretA, err := SharedSecret(aPriv, bPub)
if nil != err {
    fmt.Println(err)
    os.Exit(1)
}

// created shared secret for B
sharedSecretB, err := SharedSecret(bPriv, aPub)
if nil != err {
    fmt.Println(err)
    os.Exit(1)
}

fmt.Printf("Shared key (A):\t\t%x\n", sharedSecretA)
fmt.Printf("Shared key (B):\t\t%x\n", sharedSecretB)

```
