package shared

// KeyExchange - interface for different types key exchange
type KeyExchange interface {
	Bytes() (bytes []byte, err error)
	String() (str string)
	PublicKey() (kxPub KeyExchange)
	SharedSecret(kxPub KeyExchange) (sharedsecret []byte, err error)
	PublicKeyInstance() (pubKey []byte)
	IsPrivateKey() (p bool)
	IsPublicKey() (p bool)
	KeyType() (kxt KeyXType)
}
