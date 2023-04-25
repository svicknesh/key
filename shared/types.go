package shared

type KeyType uint8  // new type to define key types to be generated
type KeyXType uint8 // new type to define key exchanges to be generated

const (
	Unknown KeyType = iota

	// ED25519 - generates an ED25519 256 bit key
	ED25519

	// ECDSA256 - generate an ECDSA 256 bit key
	ECDSA256

	// ECDSA384 - generate an ECDSA 384 bit key
	ECDSA384

	// ECDSA521 - generate an ECDSA 512 bit key
	ECDSA521

	// RSA2048 - generate an RSA 2048 bit key
	RSA2048

	// RSA4096 - generate an RSA 4096 bit key
	RSA4096

	// RSA4096 - generate an RSA 4096 bit key
	RSA8192
)

const (
	// CURVE25519 - generates a Curve25519 key exchange
	CURVE25519 KeyXType = iota + 101

	// ECDH256 - generates a EC Diffie-Hellman 256-bit key exchange
	ECDH256

	// ECDH384 - generates a EC Diffie-Hellman 384-bit key exchange
	ECDH384

	// ECDH521 - generates a EC Diffie-Hellman 521-bit key exchange
	ECDH521
)

// String - returns string name for a given key type
func (kt KeyType) String() (str string) {

	ktys := []string{"unknown", "ed25519", "ecdsa256", "ecdsa384", "ecdsa521", "rsa2048", "rsa4096", "rsa8192"}

	ktInt := int(kt)

	if ktInt > len(ktys) {
		return ktys[0] // if an unknown key type is given, return unknown
	}

	return ktys[ktInt]

	/*
		switch kt {

		case Unknown:
			return "unknown"

		case ED25519:
			return "ed25519"

		case ECDSA256:
			return "ecdsa256"

		case ECDSA384:
			return "ecdsa384"

		case ECDSA521:
			return "ecdsa521"

		case RSA2048:
			return "rsa2048"

		case RSA4096:
			return "rsa4096"

		case RSA8192:
			return "rsa8192"

		default:
			return "unsupported key type"
		}
	*/

}

// String - returns string name for a given key exchange type
func (kx KeyXType) String() (str string) {

	switch kx {
	case CURVE25519:
		return "curve25519"

	case ECDH256:
		return "ecdh256"

	case ECDH384:
		return "ecdh384"

	case ECDH521:
		return "ecdh521"

	default:
		return "unsupported key exchange type"
	}

}
