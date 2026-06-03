package key_test

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"math/bits"
	"testing"

	"github.com/svicknesh/key/v2"
	"github.com/svicknesh/key/v2/asym/ec"
	"github.com/svicknesh/key/v2/shared"
	"golang.org/x/crypto/sha3"
)

// hashMsg returns a SHA3-256 hash of "hello, world" for use as test payload.
func hashMsg(t *testing.T) []byte {
	t.Helper()
	s := sha3.New256()
	s.Write([]byte("hello, "))
	s.Write([]byte("world"))
	return s.Sum(nil)
}

// testAsymKey exercises the full generate → sign → verify lifecycle for a key type.
func testAsymKey(t *testing.T, kt shared.KeyType) {
	t.Helper()

	k, err := key.GenerateKey(kt)
	if err != nil {
		t.Fatalf("GenerateKey(%s): %v", kt, err)
	}

	if !k.IsPrivateKey() {
		t.Errorf("%s: generated key should be private", kt)
	}
	if k.IsPublicKey() {
		t.Errorf("%s: generated key should not be marked public", kt)
	}
	if k.KeyType() != kt {
		t.Errorf("%s: KeyType() = %s, want %s", kt, k.KeyType(), kt)
	}
	if k.PrivateKeyInstance() == nil {
		t.Errorf("%s: PrivateKeyInstance() is nil", kt)
	}

	// String round-trip
	k2, err := key.NewKeyFromStr(k.String())
	if err != nil {
		t.Fatalf("%s: NewKeyFromStr(private): %v", kt, err)
	}

	// Extract public key
	kPub, err := k.PublicKey()
	if err != nil {
		t.Fatalf("%s: PublicKey(): %v", kt, err)
	}
	if !kPub.IsPublicKey() {
		t.Errorf("%s: PublicKey() result should be public", kt)
	}
	if kPub.IsPrivateKey() {
		t.Errorf("%s: PublicKey() result should not be private", kt)
	}
	if kPub.PublicKeyInstance() == nil {
		t.Errorf("%s: PublicKeyInstance() is nil", kt)
	}

	h := hashMsg(t)

	// Sign with original private key, verify with extracted public key
	signed, err := k.Sign(h)
	if err != nil {
		t.Fatalf("%s: Sign: %v", kt, err)
	}
	if !kPub.Verify(signed, h) {
		t.Errorf("%s: Verify failed on valid signature", kt)
	}

	// Sign with string-round-tripped key
	signed2, err := k2.Sign(h)
	if err != nil {
		t.Fatalf("%s: Sign (string round-trip): %v", kt, err)
	}
	if !kPub.Verify(signed2, h) {
		t.Errorf("%s: Verify failed on signature from string round-trip key", kt)
	}

	// Tampered payload must not verify
	tampered := make([]byte, len(h))
	copy(tampered, h)
	tampered[0] ^= 0xff
	if kPub.Verify(signed, tampered) {
		t.Errorf("%s: Verify should fail on tampered payload", kt)
	}

	// Sign with public key must return error
	_, err = kPub.Sign(h)
	if err == nil {
		t.Errorf("%s: Sign with public key should return an error", kt)
	}

	// Verify with private key should return false (no public key set)
	if k.Verify(signed, h) {
		t.Errorf("%s: Verify with private key should return false", kt)
	}

	// JSON marshal round-trip
	jb, err := json.Marshal(k)
	if err != nil {
		t.Fatalf("%s: MarshalJSON: %v", kt, err)
	}
	kFromJSON, err := key.NewKeyFromBytes(jb)
	if err != nil {
		t.Fatalf("%s: NewKeyFromBytes(json): %v", kt, err)
	}
	if kFromJSON.KeyType() != kt {
		t.Errorf("%s: JSON round-trip KeyType = %s, want %s", kt, kFromJSON.KeyType(), kt)
	}

	// Public key round-trip via string
	kPub2, err := key.NewKeyFromStr(kPub.String())
	if err != nil {
		t.Fatalf("%s: NewKeyFromStr(public): %v", kt, err)
	}
	if !kPub2.IsPublicKey() {
		t.Errorf("%s: reconstructed public key should be public", kt)
	}
}

func TestED25519(t *testing.T)  { testAsymKey(t, key.ED25519) }
func TestECDSA256(t *testing.T) { testAsymKey(t, key.ECDSA256) }
func TestECDSA384(t *testing.T) { testAsymKey(t, key.ECDSA384) }
func TestECDSA521(t *testing.T) { testAsymKey(t, key.ECDSA521) }
func TestRSA2048(t *testing.T)  { testAsymKey(t, key.RSA2048) }

func TestRSA4096(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping slow RSA4096 generation")
	}
	testAsymKey(t, key.RSA4096)
}

func TestRSA8192(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping slow RSA8192 generation")
	}
	testAsymKey(t, key.RSA8192)
}

// ---- Parse from fixed JWK strings ----

func TestED25519FromJWKStr(t *testing.T) {
	const jwkStr = `{"crv":"Ed25519","d":"vUjQ3PaX8iqHA0Q58Wf7mN8h-oMgAE_cFQDfi0Sr2Js","kty":"OKP","x":"etHd2wg1POjqvQZ3yhiwwU2JRwCtcqzYQIOmp7BnnSo"}`
	k, err := key.NewKeyFromStr(jwkStr)
	if err != nil {
		t.Fatalf("NewKeyFromStr: %v", err)
	}
	if k.KeyType() != key.ED25519 {
		t.Errorf("KeyType = %s, want ED25519", k.KeyType())
	}

	kPub, err := k.PublicKey()
	if err != nil {
		t.Fatalf("PublicKey: %v", err)
	}

	h := hashMsg(t)
	signed, err := k.Sign(h)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if !kPub.Verify(signed, h) {
		t.Error("Verify failed")
	}

	// JSON marshal round-trip
	jb, err := json.Marshal(k)
	if err != nil {
		t.Fatalf("MarshalJSON: %v", err)
	}
	k2, err := key.NewKeyFromBytes(jb)
	if err != nil {
		t.Fatalf("NewKeyFromBytes: %v", err)
	}
	if k2.KeyType() != key.ED25519 {
		t.Errorf("JSON round-trip KeyType = %s", k2.KeyType())
	}
}

func TestECDSAFromJWKStr(t *testing.T) {
	const jwkStr = `{"crv":"P-256","d":"rBaI7vXUerW0sG-WcOaH61F-Y2Nyzfg7UfkHNtdiILM","kty":"EC","x":"be9tCZco72RBy5z42K6sv7dOE83Or6QVwKg6FpI0kOI","y":"cSqh32Cw9MdVF47ZdM79mOHIAysmgnwNkf33rfwZKVo","kid":"my-custom-key-identifier"}`
	k, err := key.NewKeyFromStr(jwkStr)
	if err != nil {
		t.Fatalf("NewKeyFromStr: %v", err)
	}
	if k.KeyType() != key.ECDSA256 {
		t.Errorf("KeyType = %s, want ECDSA256", k.KeyType())
	}

	kPub, err := k.PublicKey()
	if err != nil {
		t.Fatalf("PublicKey: %v", err)
	}

	h := hashMsg(t)
	signed, err := k.Sign(h)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if !kPub.Verify(signed, h) {
		t.Error("Verify failed")
	}
}

func TestRSAFromJWKStr(t *testing.T) {
	const jwkStr = `{"d":"z6lGQWkYjZQ1bb_tqv3lGYF0rmUUcOhnHngvWvk6QTxyrgLLGUK_1Ds8-ZUhfyi6HrtnFAwrrpSYEPyBRZiVpmmG_P4UzivLYLKCink3I_xaWs1Z8AMyrAErYIggFOMqEw_i08PXl_CNUAN0IFgNXtVAgg96vA28uE_z3TO4lvjwEQO1g7N7ZlC_oKuxrKAZTe2ZJ5wOvrQ_dLELzRKWyp94ZsPswF7y8XZHrNmuotKo1awaHDxWr7gmr-U95lSoujLBwjxk9NC6PAE2QjQGy6c2yCABHnFG4JZNbqfNmSSACpfNdAZT06pcyToMOybzvov4FlusS1xWPC5_3TyYoQ","dp":"iZ4Fni_E9HNygI4OUGom3COPcDvKY6Qmh4JIygmSjVgpqf0qdYc0kfagK6u1Uvufs0paHCi5RJAQcUOmTzxn6rEnvKKMZhWyzx7oO_0w93TQWirOd-IyhjurEv5H42R8UqF2o1VO6wJilskZxov_uv7TpT5y7Ij4Bpala1Fbh5k","dq":"6IJG4d_T2rfNEZKqGFuK0LOydHBCsLHXeNeqEJgiDEljw082EWm6nh4I9_4G1xBKlqIRhpH2JKMnHJMWNBE-kL-MoOP890azoehfksaxIwWmOLP4DgZilxVQkzaYFvAZlSLFhyB1y0b8tRLHohVGRgzzuJ6TELN3Vn-8wXm9OvU","e":"AQAB","kty":"RSA","n":"4kNUw1ojxWfBUxSeScX5BqVo5j7OeMQe_yIPkLJwFy6DuDs_5aMYEokcbhJXAR7MXfJyoaKGxKzpNPGrus3DF0pFRkKMJ4QjGzv6WiJ0qixzvsc_gtMSQEIEmGZ0lC1U3y5aSZCzSG03f2apc47c-ve6Q-J7q_Pdakgom6tUDFKOBn6QLFcrlNXMgOyBkQ-Q0llG0SQWd7AOJSwZLvbdhpJuIHPm0uBPq1R8ZKQFBmoL8Nx9gWHPzFBJ8k8uyxqAHU627Kv5fEwe8ZGhbG7IG8rBEER318K3W3eH_rTgR3UQdlwfAYO3cuu_TJUgubrbbtijv978U-44o7gqPnSnVQ","p":"8kIMjsNE2sDm9pOLjxfndBGn1HQeVafYoyr48LBXZ6N3Apyh_4CqC_IRxULkqE_zAo0uaX01K4QRQUqq3rBfcAs9Ke1YPCQtASj_0gxXvy6SgC7tu_hJm4Yh5Cj5tLTYp34u3GoanRs0_YsCbMhPbcVq9lbgiJ5oXcjPdaOkfvk","q":"7xkCvHFhJHnW2TlU5qPUTBseXToJVL8PSXgnE8iwqgpbEMhNrEeAKoRu14zKhQL3koCc-3yqtkBPLgGT5vsKrD6Sj9Cf0iA4FAEM4wLfKSwVDtO7pAHRbySMWh6U7Zdk-CX-jbMUk9MPHaN2PYzitc8fJCQeWUHdcEe9EUlhFj0","qi":"z7WCpvGekTst0g49JmwBuGxdD-fSKZPXyh_CWE53vE8K7mPaoclqpCdg3bbbluSSPj61AzNiKWfRujGUAhgH0kZ6yNoP0lXyFaS8Hy-jTQ8sd94H2ns1n5kuyBS7ttBwBWWH3wuwavsTIFZFmr7weIqu_Pc9U7in0x0f8zscGHU"}`
	k, err := key.NewKeyFromStr(jwkStr)
	if err != nil {
		t.Fatalf("NewKeyFromStr: %v", err)
	}
	if k.KeyType() != key.RSA2048 {
		t.Errorf("KeyType = %s, want RSA2048", k.KeyType())
	}

	kPub, err := k.PublicKey()
	if err != nil {
		t.Fatalf("PublicKey: %v", err)
	}

	h := hashMsg(t)
	signed, err := k.Sign(h)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if !kPub.Verify(signed, h) {
		t.Error("Verify failed")
	}
}

// ---- NewFromRawKey ----

func TestNewFromRawKey(t *testing.T) {
	rawKey, err := ec.Generate(key.ECDSA256)
	if err != nil {
		t.Fatalf("ec.Generate: %v", err)
	}

	k, err := key.NewFromRawKey(rawKey.PrivateKeyInstance())
	if err != nil {
		t.Fatalf("NewFromRawKey: %v", err)
	}
	if k.KeyType() != key.ECDSA256 {
		t.Errorf("KeyType = %s, want ECDSA256", k.KeyType())
	}
}

// ---- Key exchange ----

func testKX(t *testing.T, kxt shared.KeyXType) {
	t.Helper()

	a, err := key.GenerateKeyExchange(kxt)
	if err != nil {
		t.Fatalf("GenerateKeyExchange(%s) A: %v", kxt, err)
	}
	b, err := key.GenerateKeyExchange(kxt)
	if err != nil {
		t.Fatalf("GenerateKeyExchange(%s) B: %v", kxt, err)
	}

	if a.KeyType() != kxt {
		t.Errorf("%s: a.KeyType() = %s", kxt, a.KeyType())
	}
	if a.Length() <= 0 {
		t.Errorf("%s: a.Length() = %d, want > 0", kxt, a.Length())
	}

	aPub := a.PublicKey()
	bPub := b.PublicKey()

	if aPub.Length() <= 0 {
		t.Errorf("%s: aPub.Length() = %d, want > 0", kxt, aPub.Length())
	}

	ssA, err := a.SharedSecret(bPub)
	if err != nil {
		t.Fatalf("%s: a.SharedSecret: %v", kxt, err)
	}
	ssB, err := b.SharedSecret(aPub)
	if err != nil {
		t.Fatalf("%s: b.SharedSecret: %v", kxt, err)
	}

	if len(ssA) == 0 {
		t.Errorf("%s: shared secret A is empty", kxt)
	}
	if base64.StdEncoding.EncodeToString(ssA) != base64.StdEncoding.EncodeToString(ssB) {
		t.Errorf("%s: shared secrets do not match", kxt)
	}

	// Bytes round-trip
	ab, err := a.Bytes()
	if err != nil {
		t.Fatalf("%s: a.Bytes(): %v", kxt, err)
	}
	aFromBytes, err := key.NewKXFromBytes(ab)
	if err != nil {
		t.Fatalf("%s: NewKXFromBytes: %v", kxt, err)
	}
	if aFromBytes.KeyType() != kxt {
		t.Errorf("%s: bytes round-trip KeyType = %s", kxt, aFromBytes.KeyType())
	}
}

func TestKXCurve25519(t *testing.T) { testKX(t, key.CURVE25519) }
func TestKXECDH256(t *testing.T)    { testKX(t, key.ECDH256) }
func TestKXECDH384(t *testing.T)    { testKX(t, key.ECDH384) }
func TestKXECDH521(t *testing.T)    { testKX(t, key.ECDH521) }

// ---- KX from fixed strings ----

func TestKXCurve25519FromStr(t *testing.T) {
	const aStr = "ybAlYu1qLcRoiMZKDfuFy8yUTU2TxXRpoYY4xvCjmUfq"
	const bStr = "yR0cwXiWjYYPP_MUPwzrZb8qOdEHBfR6RvrCTGEa4GLL"

	a, err := key.NewKXFromStr(aStr)
	if err != nil {
		t.Fatalf("NewKXFromStr A: %v", err)
	}
	b, err := key.NewKXFromStr(bStr)
	if err != nil {
		t.Fatalf("NewKXFromStr B: %v", err)
	}

	if a.KeyType() != key.CURVE25519 {
		t.Errorf("KeyType = %s, want CURVE25519", a.KeyType())
	}

	ssA, err := a.SharedSecret(b.PublicKey())
	if err != nil {
		t.Fatalf("a.SharedSecret: %v", err)
	}
	ssB, err := b.SharedSecret(a.PublicKey())
	if err != nil {
		t.Fatalf("b.SharedSecret: %v", err)
	}
	if len(ssA) == 0 {
		t.Error("shared secret A is empty")
	}
	if base64.StdEncoding.EncodeToString(ssA) != base64.StdEncoding.EncodeToString(ssB) {
		t.Error("shared secrets do not match")
	}

	t.Logf("A length=%d  B length=%d", a.Length(), b.Length())
	t.Logf("A pub length=%d", a.PublicKey().Length())
}

func TestKXECDHFromStr(t *testing.T) {
	const aStr = "0x7jZ3qC9cFxxTDIXtTDagJ8Ob0Sbv14KceWNaeXkRem"
	const bStr = "01ZJoNmpMI1uL9g7deOd9SBnkjlkciN_hNzVS0JSLmkg"

	a, err := key.NewKXFromStr(aStr)
	if err != nil {
		t.Fatalf("NewKXFromStr A: %v", err)
	}
	b, err := key.NewKXFromStr(bStr)
	if err != nil {
		t.Fatalf("NewKXFromStr B: %v", err)
	}

	ssA, err := a.SharedSecret(b.PublicKey())
	if err != nil {
		t.Fatalf("a.SharedSecret: %v", err)
	}
	ssB, err := b.SharedSecret(a.PublicKey())
	if err != nil {
		t.Fatalf("b.SharedSecret: %v", err)
	}
	if len(ssA) == 0 {
		t.Error("shared secret A is empty")
	}
	if base64.StdEncoding.EncodeToString(ssA) != base64.StdEncoding.EncodeToString(ssB) {
		t.Error("shared secrets do not match")
	}
}

// ---- KX length encoding ----

func TestKXLengthEncoding(t *testing.T) {
	a, err := key.GenerateKeyExchange(key.CURVE25519)
	if err != nil {
		t.Fatalf("GenerateKeyExchange: %v", err)
	}

	aPrivBytes, err := a.Bytes()
	if err != nil {
		t.Fatalf("Bytes: %v", err)
	}
	aPub := a.PublicKey()
	aPubBytes, err := aPub.Bytes()
	if err != nil {
		t.Fatalf("PublicKey.Bytes: %v", err)
	}

	privLen := uint64(a.Length())
	pubLen := uint64(aPub.Length())
	privBuf := make([]byte, 8)
	pubBuf := make([]byte, 8)
	binary.BigEndian.PutUint64(privBuf, privLen)
	binary.BigEndian.PutUint64(pubBuf, pubLen)

	var merged []byte
	merged = append(privBuf[bits.LeadingZeros64(privLen)>>3:], aPrivBytes...)
	merged = append(merged, pubBuf[bits.LeadingZeros64(pubLen)>>3:]...)
	merged = append(merged, aPubBytes...)

	if len(merged) == 0 {
		t.Error("merged bytes should not be empty")
	}
}

// ---- Type lookup ----

func TestGetKeyType(t *testing.T) {
	cases := []struct {
		name string
		want shared.KeyType
	}{
		{"ed25519", key.ED25519},
		{"ecdsa256", key.ECDSA256},
		{"ecdsa384", key.ECDSA384},
		{"ecdsa521", key.ECDSA521},
		{"rsa2048", key.RSA2048},
		{"rsa4096", key.RSA4096},
		{"rsa8192", key.RSA8192},
		{"ECDSA384", key.ECDSA384}, // case-insensitive
		{"unknown", shared.KeyType(0)},
	}
	for _, tc := range cases {
		got := key.GetKeyType(tc.name)
		if got != tc.want {
			t.Errorf("GetKeyType(%q) = %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestGetKeyXType(t *testing.T) {
	cases := []struct {
		name string
		want shared.KeyXType
	}{
		{"curve25519", key.CURVE25519},
		{"ecdh256", key.ECDH256},
		{"ecdh384", key.ECDH384},
		{"ecdh521", key.ECDH521},
		{"CURVE25519", key.CURVE25519}, // case-insensitive
		{"unknown", shared.KeyXType(0)},
	}
	for _, tc := range cases {
		got := key.GetKeyXType(tc.name)
		if got != tc.want {
			t.Errorf("GetKeyXType(%q) = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// ---- JSON serialisation of KeyType / KeyXType ----

func TestKeyTypeJSON(t *testing.T) {
	types := []shared.KeyType{key.ED25519, key.ECDSA256, key.ECDSA384, key.ECDSA521, key.RSA2048, key.RSA4096, key.RSA8192}
	for _, kt := range types {
		b, err := json.Marshal(kt)
		if err != nil {
			t.Fatalf("json.Marshal(%s): %v", kt, err)
		}
		var kt2 shared.KeyType
		if err := json.Unmarshal(b, &kt2); err != nil {
			t.Fatalf("json.Unmarshal(%s): %v", kt, err)
		}
		if kt2 != kt {
			t.Errorf("KeyType JSON round-trip: got %s, want %s", kt2, kt)
		}
	}
}

func TestKeyXTypeJSON(t *testing.T) {
	types := []shared.KeyXType{key.CURVE25519, key.ECDH256, key.ECDH384, key.ECDH521}
	for _, kxt := range types {
		b, err := json.Marshal(kxt)
		if err != nil {
			t.Fatalf("json.Marshal(%s): %v", kxt, err)
		}
		var kxt2 shared.KeyXType
		if err := json.Unmarshal(b, &kxt2); err != nil {
			t.Fatalf("json.Unmarshal(%s): %v", kxt, err)
		}
		if kxt2 != kxt {
			t.Errorf("KeyXType JSON round-trip: got %s, want %s", kxt2, kxt)
		}
	}
}

// ---- Error cases ----

func TestNewKeyFromBytesErrors(t *testing.T) {
	_, err := key.NewKeyFromBytes([]byte("not valid json"))
	if err == nil {
		t.Error("expected error for invalid JWK bytes")
	}

	_, err = key.NewKeyFromStr("")
	if err == nil {
		t.Error("expected error for empty JWK string")
	}
}

func TestNewKXFromBytesEmptyInput(t *testing.T) {
	_, err := key.NewKXFromBytes(nil)
	if err == nil {
		t.Error("expected error for nil KX bytes")
	}

	_, err = key.NewKXFromBytes([]byte{})
	if err == nil {
		t.Error("expected error for empty KX bytes")
	}
}

func TestGenerateKeyUnknownType(t *testing.T) {
	_, err := key.GenerateKey(shared.KeyType(0))
	if err == nil {
		t.Error("expected error for unknown KeyType")
	}
}

func TestGenerateKeyExchangeUnknownType(t *testing.T) {
	_, err := key.GenerateKeyExchange(shared.KeyXType(0))
	if err == nil {
		t.Error("expected error for unknown KeyXType")
	}
}
