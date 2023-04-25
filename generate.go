package key

import (
	"errors"
	"fmt"

	"github.com/svicknesh/key/v2/asym/ec"
	"github.com/svicknesh/key/v2/asym/ed"
	"github.com/svicknesh/key/v2/asym/r"
	"github.com/svicknesh/key/v2/kx/crv"
	"github.com/svicknesh/key/v2/kx/ecdhc"
	"github.com/svicknesh/key/v2/shared"
)

const (

	// Unknown - unknown key type
	Unknown = shared.Unknown

	// ED25519 - generates an ED25519 256 bit key
	ED25519 = shared.ED25519

	// ECDSA256 - generate an ECDSA 256 bit key
	ECDSA256 = shared.ECDSA256

	// ECDSA384 - generate an ECDSA 384 bit key
	ECDSA384 = shared.ECDSA384

	// ECDSA521 - generate an ECDSA 512 bit key
	ECDSA521 = shared.ECDSA521

	// RSA2048 - generate an RSA 2048 bit key
	RSA2048 = shared.RSA2048

	// RSA4096 - generate an RSA 4096 bit key
	RSA4096 = shared.RSA4096

	// RSA4096 - generate an RSA 4096 bit key
	RSA8192 = shared.RSA8192
)

const (
	// CURVE25519 - generates a Curve25519 key exchange
	CURVE25519 = shared.CURVE25519

	// ECDH256 - generates a EC Diffie-Hellman 256-bit key exchange
	ECDH256 = shared.ECDH256

	// ECDH384 - generates a EC Diffie-Hellman 384-bit key exchange
	ECDH384 = shared.ECDH384

	// ECDH521 - generates a EC Diffie-Hellman 521-bit key exchange
	ECDH521 = shared.ECDH521
)

// GenerateKey - generates a new key
func GenerateKey(kt shared.KeyType) (k shared.Key, err error) {

	switch kt {
	case ED25519:
		k, err = ed.Generate()
	case ECDSA256:
		k, err = ec.Generate(shared.ECDSA256)
	case ECDSA384:
		k, err = ec.Generate(shared.ECDSA384)
	case ECDSA521:
		k, err = ec.Generate(shared.ECDSA521)
	case RSA2048:
		k, err = r.Generate(shared.RSA2048)
	case RSA4096:
		k, err = r.Generate(shared.RSA4096)
	case RSA8192:
		k, err = r.Generate(shared.RSA8192)

	default:
		err = errors.New("unsupported key type given for asymetric generation")
	}

	if nil != err {
		return nil, fmt.Errorf("generatekey: %w", err)
	}

	return k, nil
}

// GenerateKeyExchange - generates a new key exchange public/private
func GenerateKeyExchange(kxt shared.KeyXType) (kx shared.KeyExchange, err error) {

	switch kxt {
	case CURVE25519:
		kx, err = crv.Generate()
	case ECDH256:
		kx, err = ecdhc.Generate(shared.ECDH256)
	case ECDH384:
		kx, err = ecdhc.Generate(shared.ECDH384)
	case ECDH521:
		kx, err = ecdhc.Generate(shared.ECDH521)
	default:
		err = errors.New("unsupported key type given for exchange generation")
	}

	if nil != err {
		return nil, fmt.Errorf("generatekeyexchange: %w", err)
	}

	return kx, nil
}
