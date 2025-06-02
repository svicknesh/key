package shared

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/svicknesh/enum2str"
)

type KeyType uint8  // new type to define key types to be generated
type KeyXType uint8 // new type to define key exchanges to be generated

const (

	// ED25519 - generates an ED25519 256 bit key
	ED25519 KeyType = iota + 1

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
	CURVE25519 KeyXType = iota + 1

	// ECDH256 - generates a EC Diffie-Hellman 256-bit key exchange
	ECDH256

	// ECDH384 - generates a EC Diffie-Hellman 384-bit key exchange
	ECDH384

	// ECDH521 - generates a EC Diffie-Hellman 521-bit key exchange
	ECDH521
)

var keyTypeMap = map[string]KeyType{
	"ed25519":  ED25519,
	"ecdsa256": ECDSA256,
	"ecdsa384": ECDSA384,
	"ecdsa521": ECDSA521,
	"rsa2048":  RSA2048,
	"rsa4096":  RSA4096,
	"rsa8192":  RSA8192,
}

var keyXTypeMap = map[string]KeyXType{
	"curve25519": CURVE25519,
	"ecdh256":    ECDH256,
	"ecdh384":    ECDH384,
	"ecdh521":    ECDH521,
}

// String - returns string name for a given key type
func (kt KeyType) String() (str string) {
	return enum2str.String(kt, "unknown", "ed25519", "ecdsa256", "ecdsa384", "ecdsa521", "rsa2048", "rsa4096", "rsa8192")
}

// String - returns string name for a given key exchange type
func (kx KeyXType) String() (str string) {
	return enum2str.String(kx, "unknown", "curve25519", "ecdh256", "ecdh384", "ecdh521")
}

// MarshalJSON - serializes the `KeyType` as a JSON string.
func (kt KeyType) MarshalJSON() ([]byte, error) {
	return json.Marshal(kt.String())
}

// UnmarshalJSON - deserializes a JSON string into a `KeyType`.
func (kt *KeyType) UnmarshalJSON(data []byte) error {
	// Remove surrounding quotes and unescape any escaped characters
	strVal, err := strconv.Unquote(string(data))
	if err != nil {
		return fmt.Errorf("KeyType.UnmarshalJSON: invalid JSON string %s → %w", string(data), err)
	}

	*kt = GetKeyType(strVal)
	return nil
}

// GetKeyType - returns key type from its name
func GetKeyType(name string) KeyType {
	if kt, ok := keyTypeMap[strings.ToLower(name)]; ok {
		return kt
	}
	return KeyType(0)
}

// MarshalJSON - serializes the `KeyXType` as a JSON string.
func (kx KeyXType) MarshalJSON() ([]byte, error) {
	return json.Marshal(kx.String())
}

// UnmarshalJSON - deserializes a JSON string into a `KeyXType`.
func (kx *KeyXType) UnmarshalJSON(data []byte) error {
	strVal, err := strconv.Unquote(string(data))
	if err != nil {
		return fmt.Errorf("KeyXType.UnmarshalJSON: invalid JSON string %s → %w", string(data), err)
	}

	*kx = GetKeyXType(strVal)
	return nil
}

// GetKeyXType - returns key exchange type from its name
func GetKeyXType(name string) KeyXType {
	if kx, ok := keyXTypeMap[strings.ToLower(name)]; ok {
		return kx
	}
	return KeyXType(0)
}
