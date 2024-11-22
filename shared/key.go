package shared

// Key - interface for different types of asymetric keys
type Key interface {
	Bytes() (bytes []byte, err error)
	String() (str string)
	PublicKey() (kPub Key, err error)
	PrivateKeyInstance() (privKey interface{})
	PublicKeyInstance() (pubKey interface{})
	IsPrivateKey() (p bool)
	IsPublicKey() (p bool)
	KeyType() (kt KeyType)
	Sign(hashed []byte) (signed []byte, err error)
	Verify(signed []byte, hashed []byte) (ok bool)
	MarshalJSON() (bytes []byte, err error)
	SetKeyID(kid string) (err error)
	GetKeyID() (kid string)
}
