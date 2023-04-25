package key

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"testing"

	"github.com/svicknesh/key/v2/shared"
	"golang.org/x/crypto/sha3"
)

func TestED25519Gen(t *testing.T) {

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

	fmt.Println("k is private key:", k.IsPrivateKey())
	fmt.Println("k is public key:", k.IsPublicKey())

	fmt.Println("k2 is private key:", k2.IsPrivateKey())
	fmt.Println("k2 is public key:", k2.IsPublicKey())

}

func TestECDSAGen(t *testing.T) {

	k, err := GenerateKey(ECDSA256)
	//k, err := Generate(ECDSA384)
	//k, err := Generate(ECDSA521)
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

	//h := sha256.Sum256([]byte("hello world"))
	//fmt.Println(base64.StdEncoding.EncodeToString(h[:]))

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

	//h[0] = 186
	if k2.Verify(signed, h) {
		fmt.Println("verified data for ECDSA")
	} else {
		fmt.Println("unable to verify data for ECDSA")
	}

	fmt.Println("k is private key:", k.IsPrivateKey())
	fmt.Println("k is public key:", k.IsPublicKey())

	fmt.Println("k2 is private key:", k2.IsPrivateKey())
	fmt.Println("k2 is public key:", k2.IsPublicKey())

}

func TestRSAGen(t *testing.T) {

	//k, err := GenerateKey(RSA2048)
	k, err := GenerateKey(RSA4096)
	//k, err := GenerateKey(RSA8192)
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

	//h := sha256.Sum256([]byte("hello world"))
	//fmt.Println(base64.StdEncoding.EncodeToString(h[:]))

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

	//h[0] = 186
	if k2.Verify(signed, h) {
		fmt.Println("verified data for RSA")
	} else {
		fmt.Println("unable to verify data for RSA")
	}

	fmt.Println("k is private key:", k.IsPrivateKey())
	fmt.Println("k is public key:", k.IsPublicKey())

	fmt.Println("k2 is private key:", k2.IsPrivateKey())
	fmt.Println("k2 is public key:", k2.IsPublicKey())

}

func TestED25519Str(t *testing.T) {

	k, err := NewKeyFromStr("{\"crv\":\"Ed25519\",\"d\":\"vUjQ3PaX8iqHA0Q58Wf7mN8h-oMgAE_cFQDfi0Sr2Js\",\"kty\":\"OKP\",\"x\":\"etHd2wg1POjqvQZ3yhiwwU2JRwCtcqzYQIOmp7BnnSo\"}")
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

	fmt.Println("k is private key:", k.IsPrivateKey())
	fmt.Println("k is public key:", k.IsPublicKey())

	fmt.Println("k2 is private key:", k2.IsPrivateKey())
	fmt.Println("k2 is public key:", k2.IsPublicKey())

	fmt.Println("k if of type:", k.KeyType())

}

func TestECDSAStr(t *testing.T) {

	k, err := NewKeyFromStr("{\"crv\":\"P-256\",\"d\":\"rBaI7vXUerW0sG-WcOaH61F-Y2Nyzfg7UfkHNtdiILM\",\"kty\":\"EC\",\"x\":\"be9tCZco72RBy5z42K6sv7dOE83Or6QVwKg6FpI0kOI\",\"y\":\"cSqh32Cw9MdVF47ZdM79mOHIAysmgnwNkf33rfwZKVo\"}	")
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
		fmt.Println("verified data for ECDSA")
	} else {
		fmt.Println("unable to verify data for ECDSA")
	}

	fmt.Println("k is private key:", k.IsPrivateKey())
	fmt.Println("k is public key:", k.IsPublicKey())

	fmt.Println("k2 is private key:", k2.IsPrivateKey())
	fmt.Println("k2 is public key:", k2.IsPublicKey())

}

func TestRSAStr(t *testing.T) {

	k, err := NewKeyFromStr("{\"d\":\"z6lGQWkYjZQ1bb_tqv3lGYF0rmUUcOhnHngvWvk6QTxyrgLLGUK_1Ds8-ZUhfyi6HrtnFAwrrpSYEPyBRZiVpmmG_P4UzivLYLKCink3I_xaWs1Z8AMyrAErYIggFOMqEw_i08PXl_CNUAN0IFgNXtVAgg96vA28uE_z3TO4lvjwEQO1g7N7ZlC_oKuxrKAZTe2ZJ5wOvrQ_dLELzRKWyp94ZsPswF7y8XZHrNmuotKo1awaHDxWr7gmr-U95lSoujLBwjxk9NC6PAE2QjQGy6c2yCABHnFG4JZNbqfNmSSACpfNdAZT06pcyToMOybzvov4FlusS1xWPC5_3TyYoQ\",\"dp\":\"iZ4Fni_E9HNygI4OUGom3COPcDvKY6Qmh4JIygmSjVgpqf0qdYc0kfagK6u1Uvufs0paHCi5RJAQcUOmTzxn6rEnvKKMZhWyzx7oO_0w93TQWirOd-IyhjurEv5H42R8UqF2o1VO6wJilskZxov_uv7TpT5y7Ij4Bpala1Fbh5k\",\"dq\":\"6IJG4d_T2rfNEZKqGFuK0LOydHBCsLHXeNeqEJgiDEljw082EWm6nh4I9_4G1xBKlqIRhpH2JKMnHJMWNBE-kL-MoOP890azoehfksaxIwWmOLP4DgZilxVQkzaYFvAZlSLFhyB1y0b8tRLHohVGRgzzuJ6TELN3Vn-8wXm9OvU\",\"e\":\"AQAB\",\"kty\":\"RSA\",\"n\":\"4kNUw1ojxWfBUxSeScX5BqVo5j7OeMQe_yIPkLJwFy6DuDs_5aMYEokcbhJXAR7MXfJyoaKGxKzpNPGrus3DF0pFRkKMJ4QjGzv6WiJ0qixzvsc_gtMSQEIEmGZ0lC1U3y5aSZCzSG03f2apc47c-ve6Q-J7q_Pdakgom6tUDFKOBn6QLFcrlNXMgOyBkQ-Q0llG0SQWd7AOJSwZLvbdhpJuIHPm0uBPq1R8ZKQFBmoL8Nx9gWHPzFBJ8k8uyxqAHU627Kv5fEwe8ZGhbG7IG8rBEER318K3W3eH_rTgR3UQdlwfAYO3cuu_TJUgubrbbtijv978U-44o7gqPnSnVQ\",\"p\":\"8kIMjsNE2sDm9pOLjxfndBGn1HQeVafYoyr48LBXZ6N3Apyh_4CqC_IRxULkqE_zAo0uaX01K4QRQUqq3rBfcAs9Ke1YPCQtASj_0gxXvy6SgC7tu_hJm4Yh5Cj5tLTYp34u3GoanRs0_YsCbMhPbcVq9lbgiJ5oXcjPdaOkfvk\",\"q\":\"7xkCvHFhJHnW2TlU5qPUTBseXToJVL8PSXgnE8iwqgpbEMhNrEeAKoRu14zKhQL3koCc-3yqtkBPLgGT5vsKrD6Sj9Cf0iA4FAEM4wLfKSwVDtO7pAHRbySMWh6U7Zdk-CX-jbMUk9MPHaN2PYzitc8fJCQeWUHdcEe9EUlhFj0\",\"qi\":\"z7WCpvGekTst0g49JmwBuGxdD-fSKZPXyh_CWE53vE8K7mPaoclqpCdg3bbbluSSPj61AzNiKWfRujGUAhgH0kZ6yNoP0lXyFaS8Hy-jTQ8sd94H2ns1n5kuyBS7ttBwBWWH3wuwavsTIFZFmr7weIqu_Pc9U7in0x0f8zscGHU\"}")
	//k, err := NewFromStr("{\"d\":\"dgRIC5vC0uijGjKFyHQ0taknMOpKWTJqc8F4n2bv3NyPebsGHy1dLPsTGposakAHrhMPcAbvvGS1R5NuRKFxZXElqIjdXRq7BMp5-oWulsclhLwzBaAWLh_hpjclOlJWujEMSK7dObqmO5aqgWvv1ukW0or-0nvHiVmq3Ut0tVHDSCVZTuQ6GdM5YXvjB9v7fixkqWLLfe9ddhGZ7hOFrB8MW9Gh8LmIr7Hjn7jPas4l8gtMxMg8sLJNJg30j5-HKVaRsMqJSlL5RcDjlEVL3Ru_UGdiH0ZdrWfqlN1GRzVqsEbpfPgyL_D67x2FoYVcopscByQpGHgGSZV5EiWG5fEkyHeXGW8WjLVsbWp0cPD8yUkjIuG4_79gb_USIC3Xw_WK1QvuNb0RP7lXzgzjmkSeICOdYyydauMKh3kNFRnpJb4B7970Ri5qQRGW_NOWlwVSjufE5eh4RvdkF1C14XMvB_wDt330FNpNWP_WSPLjNoICNdThShx4d4jn08nYFpBck4THmaRDPf88VtSl11tDjsoIVY13gS5_Ss7siQ-vV-tOnlOgP2JzoUIzLFq08RQYYW02XCMUiR41U5rsMFCouP8gt9Qf0NGZfDBW2i30CoDr4CJcC7OqTFzUVQXiKvjmqyyGbOQLL98nPS49s6Xy-TEgPyW0zRoXnzGlVJE\",\"dp\":\"bpsI77m-ltBW6YdJfMjpa-jUzzvGpCWOL9o8Pkw_Q-nixkYMeDcqDrvpwDlz8e0-ucTiFAi0Jl6qcgzGBx1DfoLpYLE-Bmb7rcFIg4P7N7yhXCa093z7QViw6_jVK7xXyK5sHzGRMeM5OlxtrdL3jmuSkucNmkGiCp_zkDphdIJi3fq6UMMcjXgJpKfWLt3XDRwLQjnVLjMQFiaLamUc1uLPR80E1pyrDLiiHy6URapJE2TzHuVH2_nXCHEEQyC1SRLl0XkVQCBAfqjZmg7PHtvA_rErEIdT-NKOmYPfeHkaNqAKA2gVZasDwcv4QJ9EpMlv8b69tHcHMq-sl-Qobw\",\"dq\":\"aT1KvpkWE401YpHcGeDejSAY5bHKftH_VvTwsnH3ouSFRvZabk5ZHwE-1RdwzBaPW2yld5NB0BJJE3R77iApeho_O0Bilv2yUCd4FEXaaty-pGgs62e5r1NgiW1I7zAuZ6mB5VBtD-8gQdJ7Iv2ZRdMBnWHeKFSJ11uHI-wRqFd-VTgFs9i7quyKlRSFVg59IoCCI_su2YoIRAZUNNFnm3WPu4s-f2HOJ2pwI--egBD7maTMCbmS11EBDkOMOnSxPKzJkFS04-BtEKgwu3zZrIFiMVVSjIyI7Xk5y3EWQcmcEfzq2bhsHWxxif6fITCrnlCdJM1ImgAmn6rU85SH6Q\",\"e\":\"AQAB\",\"kty\":\"RSA\",\"n\":\"pPhd6pKiAqPMNVK2WJk40anMNECJWytJh3VVKdLI6mEsTmxf-2OCmdmw7CGsdb9952DO5WkTkOWEDZbNId_Ab6pxfukqHtcXm4-OGpnEh3JGQyYnt5d9NJrPCypICkNR82sUKzgOBnbb-W5D-FjbTPOPXPzXKkbdGqGEMuF0hta-0Irq5xwHEN5cPS8XoXdWIaJ94VUCsMEM8BKb0Bw9PZiQH51wx1dZtVE-zVS3kps1DZ0j-QnFYiugeAMdoA1nYPvup5abJG615aCxSnYS7XRqY5am8kO8DQxAuDUXVDe_uxP-iTcZwF9JaJmGg6y7RAikQfYV3c2KSPhN-IXN9x--lI--WH4A2R5rsNTVqJnpWBl0YEAcjSM09AwzOtQFycgCKTRVbLttv6r5mfiflufNN7bAQmi4eJEnAWTqcM34ogxnXqC44splBDlPBBFwS90zynZE4zOoNLYP4_fQ1227-C65jc2qPSbdojBlZCDkpxPggI5C20gHyfIRsUEZaHADGnloKWwCCrDrsX7stuf1lORsl3fk7Mid5QmIzs59e64rR-bcx4wQ92uOzCQAFatBSjIrLhiZTKmKTlHj2SKnqm12w5j9hGbtOzemlVZNboD8jUOCCyNXIG02OnJ3qNG4aOxl_DV2YYTE1AzgezXcPKsyFpxi5LnHCfjbTYk\",\"p\":\"2A1NtDEYTm4WCPGvmAD2hZ8eFhYQxUG8i3PJ5A_h-AcSH3U2eU0-CkkGQ_LBW_HvV-tluZBu2BfAVtsfu6ijnqhGaIHyhbvwgEks6OBwhxVdf5182qJ3pMXxrPOIi9t-WxsZ00EYkpgX2Ugoq7biCBi6tskeuLCvxUsa8YpXHOTuVsRrEA6hI3JYvoWBAjxei4yLAjK8c0dOYPgVjgZEIzAMaUx3hCiTHtDcDYapKbAaOue3kr0sTYFJJxMSu7HHUkcPGlqXSPqUZgp8YPenaT_qtxhM3TOnCIblp095zZl0p9m7XrbPU0GH-8k7IXhMo003HyyrpHGI0IJBwOd4sw\",\"q\":\"w3ki4htBl_PCePTu4BVOFS0OaGGhVfc43D9SnsSMu3O152p9lNuS3ABVIzDT_-_ybqjavODP0bYPp8GoMwy81NBTvQPm-pM1EKRwOZBfi2KKF-e_XaDnaWoSuYxz8edQavkiF4Y-DQg26nTvaQjh7evpttUpI77Ga5fcAlhTCK-SRjhwdTxy1hCyyP9Zm8l2YvJdTuP049ONStYudR0y6QX4_BqKZPCDehkwBN-3cY7Xl4Zh6Ih-MU6BmvrhmY9sO05REMp-MLylx4_e028pTsIHgd5OFPJtt2dIYoU4whiJaiOsdz6kXO5vMxu5TUiAgCHdRXdnv0mEMTs1atbm0w\",\"qi\":\"mvstCxQ1i53EpdZDZPXx2qPdr_o7UySpRg0rhLWSRptLYxPDNRVT05nYP1vlhNL_ly7PHmrb-zxxv4pwRrCYz5tlQJpt-sWM9w87mC-6OtExs5Ah2mtTXttq1c-DSqnk8I-fhBu629h5QwlHnI6J5kRFWPU_jn5aF4b_QXc9r2V30lWCOP1c7PgxTDHtMpbY5ZFnspIzcvvnWmELaDKdkw_gBOUwzuNhCoFQLPZkNTdnZFH1ckmKeGlqrvX4gkbeifO3DkiBqgcP1FtyfMhjilvhArFcEJeMJ2dLZyHClKWyTVjEzyXP4I1nCfSJyOYU3pOmT3lSlSmuXvRSgVwCXQ\"}")
	//k, err := NewFromStr("{\"d\":\"zNKcx3if9UpTq7PjutPpJKqdGKLQUgeT498JsINIBA3SJoDFJXZLlAC3rmWOaChoK4YvDVy3IsGWMYyktQ7fmhaNnsZTVW2jXAmOPM27oBsmSYM3NWgaV-yNhqFkmkLIUpApazGWnCAzIh6eiMXC3sDf0aT6MjjuvyL5akL8szYNkA0WZUDgDkMUD5hlS9DxTyBUcTEP_IsB2MLuDDs1oivQnerAec6hSkPpqFv77zMV9EdCSdzIAgTbYjZLs7worbtkydd0pjg0uPHRD8o2Or1kAEr5DUKfP5IdKV_0ou-LmNYNRCgubNs90eyVXdt22Bh4kmPTOceQ6yCKp9W7h08il-34lzmqXny0RVQuJV19KDzDxZLPTslMtwLcmptYAUTkBT7ug9l2B4UhSGfxJKJhZKyLgfrPq09K_ELT96duSc_UsqfCyBwMY02ojflMhnDkHFI_1e0y0lCVgBSP37pH9DG4wG37JWlFwzuzL_uUIB8ZqogLIpKxeW2hco0DFzctwxoAP426cuP45LQh1smBZR0Q0Je8MMS3F1NSqe4qLhh2wsV1vm-dFAPEOGDnLQT_qn06Jt3foocRY_dUattcKsZwTNbuVwl2MoCq6eIpbalDpNXFOhzx0lC3Im4SKofXavMbpu4z6C16Cz-6_z_PHhFIRvOc9KYfD9HU0ue42Jd3HP60JXt4p_fEjz10DV28pqLHNtF5erdZFSQ3j8DdUN-NDN3Ap70ADP8Cf8x4ztwS-ajRvcqQ05AgsOrFyQKwXQzJVIalv49mG2UeCJuWzKqs1nlUYyx0LEoqhUmFtbON2JbJZI9UqMErOigy8Od1hZRDM0OKjTk2QM4eWvkDR62PNFIKNNkvfiMEwsi1hS2_DhKWG1GYB93Ij7wL7NADtTy0v_hhr9go8CUqB2IOSdkoomolx54UQqZQnTsU8tZUWcT72uoDxXii0n0cINGWfx6xccx_HemOQ3Wg3D0k_OFz3Zj4wpSFa8-C4APJJQZS0TrwywkCc58Glu9g2qjF1a9Ezhh3Ic9z_vENaKgonvBNZE4-fZFGiK_cpcggoSrvhWytFj4bT6STDSEy3DzTtwUpOeKKBTMxBGCVe3eUpcRFCJA4MJfhJBFldG-BUf30PFuhf01Te0hjAfunbjK3chWFkvsNwDYMLpFCs7fOrcXlx4zEdA5kbkV8WoUMWQruOlziA05jf_aEKFSEgOMXnfSfOSISVsvbRs8vTXaW5-vGKfxmDm-22-FMzweRT1Mu65fRbT6UCT-gvfNA5OvbZ21Qt3BR2ICN0cACdMvRlBLoo10NDfaYuAm8FqqVYLDjdhpwqj44Sv-bkUlsnyY1M0sGBrdeD_5SrfO0UQ\",\"dp\":\"nW5Nj1zoXL9LPv-17EXNL4VfmvaNGnUc1OZnd1Jw2x69_cAWRP57BpbbWQlZGcSI2i2oUycJy9C7tz2_JdwVh0Z2z5XQurLczQR0o3zaHowo-0PhA4N2pUsBtQyThUq41HXEPy3JgQyvB7-XD2zDFtSYU9wHY6QpSD7zIlc_53rjAtNnNv5T3lIObXHylVrHqmJLl7UHp_N4sHh46kpN5LyT4ab8Oc41nJk7oMd3s0Xuge2PoHPy9UjKdBehyTdqNptOGBMx6qb7WseHFlg5sytvbyWsBqg0VI2ouWSnNrkK5eRE71XXcScFfHtSPKLKoNIQddP7JXY9NmWcQI6AI-TKwgYX3r6aPlXDmm0z_Cwt7Y_jJe5f326VH25oNKLdKS-mkbBUiocWp2wCNQPmOm7S6pc-9VBvODjzGWFkBdVKm6wG-k5-EQQffnMp_YIDJwkuIxGovKh2wco1zMRs54Qtr6kJMJGA9MY4ntm92UtcaqEgmW3qmCK1OcXBWOUBCTT3d61bjFLhTiyFMpIqTA-nrTU1NoG3OnDTtNwIed9qWzNxxaEAUmqfVwEdgmYzrnF17fRJzQP-RP8SnNgaILIOvRwOVXdi2JFHPJjvqKFyGA35Q9g_UuQ7LjNf4OnPuNBAW_2MW3n7DXFgtPeOJhKzy5IgT6qoHC43iYmTwk0\",\"dq\":\"lLc3i-raERRfMn7zX7CqijrN3Zk_oxCMc0R4bl3PH7ZStkdHxNiFIN718cVqYiJlJbVLAWcOB9mkfaOsxZTb-c4C1HrjwF9QQDeXTlSKkucT2q590NGp9KHiSCm1dkgD1yfib8tkqQ5quS4OtMcIath4PvR_TdZWvgFa3iNj_ebG2XHJExayQoy6ovosMz4Inq3USzPNHmyWrtBW9eSoLBOgArRDWMSl2e9vqNxPfRS6V4hnWj32QkAGD4dqd4QcBUeBp1gJpmr3nRIcrExjMxcW3u5vybMe9_BWegGwf6bPOO1MkbIWnzZ_L8AQBV342v-j5WmprZKM3nds3vrETVD2iUsoixwJUdNYw9knBpFnPtCYqmxwpF0d3LpAxVpKaibOfngC_FTZfDJPuGVQ2pm2Rwuey3MfmwYGMLIpIsh5WqHITtyKLMODso7UzmpBRTbIWmswKqRsiOtUL2_8g0tf479_OdcERzUFRINUSHhcR8OKT31luMkpGkibhoZXVuoV4P6KT8lEw0EO6nP4ABYY4pZSHFHq8oNOf6fZ-MwrvZ4DSYK0_5M9zeKA2m2aHFHTCGq1HVUJtdKPZKG3UeCL9faiynEV6gIsIGS95D32p2PJGtxhNjr4Mwjz4f8HnC0RqNSjyBoDLamDxvYHOChpx3eXn01iyUPvYYXg8E0\",\"e\":\"AQAB\",\"kty\":\"RSA\",\"n\":\"8Hx_sW7w2Ks9YjWxtu3KyGdBcYxM46DjY068dacxUYHw4oqnBrPhe-DUb1fxKp60_qmT6D3hkAqubGplG-RkrwGMgPxePSZDR7BIFvMrXh15PPpFOEVq6FawOLgEv_Z45uWJaax7YVgU7KBN9wMbnwsxetEGqjQ7zl2Ln3NJWHb0Z_5Xf-jV-d5iNwBcoGdOyMwXAxRqIpg9lZBc-GbQ2YJKzUgLP42mPYkolx45rIrl2IbCHf2ILlzVdkoM8VnBpyKxg-BnBEmdb496mZ7aNCwiEzPuwabhdLXJjHdYe9BCOnlh5ES7xO-Ha-QJ2COvVWKeUKXeGuzn3Ffmkzkdg2RwtZ8Vfz6S9xbOhdTQCw-BE5erjH3C5iUg8MMjOHnTNBh_N2ORdrjDtmm6VNpRDWYqUX-2PrcJ-vypmcBcb2iRcpEyTh3WCyq83L2PzFkYrrWJ71pvHla4ylP3O-XW3v9Y51emMOvTzaTbSLyemA8P4GMu3uKlW8frJFQufOgFYFBy45Kj9Zt1WUnnN_LlDg8GkgpIQGUIB0TXGWkCN2NsTYod5j6BQsF3uqiTjV16A7ThBYRRlQdJD-ib_GhZm9CqIEgJs40sOv9o0N_ysWeCqfH4yBSqkww-xjult_tTHcZGsoexrL0wrAMg_1aqHJOZXc-K2QZbMiSK5sUkVhrQVvbAnszUi3fWU9xcArNoto7LpyTZhITbngxYXCMT7aRQQdlH0OSSBZkSxkxbjZBxQpJ1YtBUwC9BLrojMMtrwOZjxcSrXY_-IHZnBge_0aDuF_F-7C_THlcqqQQJbOKwfROWr6Al5hrWGPuyw54Jegqwn9asJ1OEW0MtLGBMGwC3iPukj1fppVWaTeoBXiJaxm50I4ZKFm0UuSf7sX7jjQbQDv10-f7Gv8BSjayu_4sc6a9k82ca6ZUXl2dST_o17L29acpE_f-RtWin25xPfdJXrDpmbi_D5w6sBR6vRcLZarwZheoKsXP_l_KStYs6lbzEvDn3CXiYtSCbNaWPH6ynlHKQILETZpqp9PljmuCkcuxs_LcQSPsyE-4fYL2jvN7_iX28XH68L_jRRc-QdY3VvFz9n0U_jPuOITpSlWuyhkGwrLfCZUBMv0T4pourG8UlUAbMYVxMDVJCFhcC8a3NtDbZCdMT0mU47isJMz06Hj3nEKerRZfPvxscyUegieTUMrJjX89lqtI9dUK283pxJ7N6N8eGaK2oL0QQ7AhbNyYzoQuwyFgsHH8bYGG2m6UCPhIAFcSr8SURxS2hStPHJzChbdZPhh0CqPJT_kNhv361H9JcppBDJXZWrOTLiYdPVhsb7-qc-RcPyQnoJIRK_I-5Enc6Z1rJzjeMFw\",\"p\":\"_AwNEYHiQTM8y5FWlYCE0HfeIaWB94VrtaZcLfcIe9K0TPXAB7wCNUG7xSse9QWze5W5zLoraCXrkyrvVMQEDGhTo4woAKxAg3z0kuyKux2vFaMoVu5YskTl9ziukXceAceh7GnLORefBLzu0InmXosRLpynRmiuolaJVFKW5YuIMAT3PaqA0fcWNEWRUMoBMgyOuYEuXZ07MSfwdTEP9cJajoR0gES9AgZ3xe8Uhf3yh0U-6EBpHzLfh4odYr_AP6xg2vESdD0zLGnziqYqCMzKkJUpLvYbO94jJy0gBZriy1TWlBhh2nrhBZCPvMpYCe913XG07Ppxz5nBEAiCcdATJ3-Ijq1zFRTn98AAQj3QOB7fj3DZUaV8WEA8p_JaV8vRDgIHFa3-rWj0mw7MTUD0TtYtizZhWdy2M2WdUoozGYaa3yIET-Mvg4pn7h01ntr0FomYY4Sryz-0f13cil3AkqGqntOGsLCxCi1em6PavVzbrNCgoshRekytxcqqwWsGmg_K0_toSftH21-oVd1W9vgBBhpwgdRf0auLVzinnmBtbGotT7-SV951LlUtcCG_eC5TpY5WslRpXSFLjq6XLLBBDJmFSY1KkEBqeYsogLqfRWVDSryQx1AH1OJd_Hw1SLZp28euclXA1q7DffNxBuXAgoxYxZwzJ5mSEdU\",\"q\":\"9EIIQgUyVlh2Mii2m7j6vq8MDSI6t_p0JiQUf0bM9BbAu2cw0w2nCSY-L5MqLI5FNqOa-4j40fi2xDGYnMJhbvDF7ZXIaNOr38Qz018MWmUuRMQRStepteJ0fzX3dEZuuuASoRJqgPnGfKZLcP3xGheNfRKiBlLX7fw7sEeqFsfeBhYPgYgpvF8w8zZV-s4FSociVKmVE7udlDw9_XuKn2qd8buy1p5bUzhaYvSyn14qjPvZKdN6ZoMdFgPwcQKaECohsB9QqU1L-aWMr78EtK5q34gyjoZMULsfnm5KGOoJxp8ESsXjchDZqUfDx0WtFuhEgD9UhAl1qHCuciv7R0_6NvSAgjEE0uBI03lxPFLGP0IKQkTFQABsxWZJ-8kHVF_hcZZNz-GMwTbnujqy8lnZ8mKbyxhwFWM7uN1hNEXUXgyERUUAVEMV8TVwWOPiYbLrNTwUnnjXWIXxDmkqiBbpZfEb5CuQQKCggWVi4_477HGY4V6Wmo9xIZdBeSdQjQ1jZjSAdSX4xDRQmpyVvkPicNWl3P77SysOU3iCrfTqxoN6CWfIr3v5Lk-Fahfes7DnIlxla4C0vH7cAKyiQ4Smfb00UhhA8ml89McvKW6JJq1A1Bz5Tk-5dzLYExyjIkBfz8tRa5PTjMCigBhRFUJjsxJN-31jrcSYN0KfsDs\",\"qi\":\"9k4oK-j9ZiB8hkAAOJnvIM6Ojk2JO6H24tBb6CAPxcDCsf8bQqBYWHW1-otxNMUQ5gahpuwgD1iUImSbX5NTQl5oNPcqWqsx6stamxJ_1dBpM9VgqbF3NZRuaIHPjbLlD1eSOZcq7jOEjy6Z204BesNeVbPLH0Cgg0RAXtEYVccKHsZw3HW_tcSM9Q_qcIZHGwpD-r0fhSSG3tyFRCSIFL7c8259fnWMV57gHkdUgWvWZ9fPVFiPkfv373NXedY_Rt_bpRyjZQwaz_09uhYvcBH_8ohrYi8PXYlXzpFzzVR1KrpNSlpK_ZkKy-NP5DPdqpCFfhuwQbzTeSeJEOXfagQPxHQwxk2eUjAVkfbeAyAIiFdV-AiDzLrq7dRZZ-zqJUKBU2bgb-oCDVyfqYIRUqDf416qaX0SpGEf53qCUvySzGfm2HbkS_1S-vzrgMS7bfaPb_51fqHT96qD4e-iNlUrwy8DW2B3XtLqXCednWUEhI_OfZZ5664WFCIqTRCkeJHX7BQDuO0spLCCXAL_a1bsXFI64WSM_Zj_Mayq7jE4LNcRiu1CaRk8iDKyAwgxqdRvo6Rixe2i99dyktOc_6tgHttXq0npbwP7Y3EII4NGtF1Jvga6WA9Wv92_A_bp5zsKI06OhmBGfC-I91GoOexcYaxsBOtWTIhoxOkofi0\"}")
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
		fmt.Println("verified data for RSA")
	} else {
		fmt.Println("unable to verify data for RSA")
	}

	fmt.Println("k is private key:", k.IsPrivateKey())
	fmt.Println("k is public key:", k.IsPublicKey())

	fmt.Println("k2 is private key:", k2.IsPrivateKey())
	fmt.Println("k2 is public key:", k2.IsPublicKey())

}

func TestKXCurve25519Gen(t *testing.T) {

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

}

func TestKXECDHGen(t *testing.T) {

	// A

	a, err := GenerateKeyExchange(shared.ECDH256)
	if nil != err {
		fmt.Println(err)
		os.Exit(1)
	}
	//fmt.Println(a.KeyType())

	aPub := a.PublicKey()

	fmt.Println("A private key:\t", a)
	fmt.Println("A public key:\t", aPub)

	// end A

	// B

	b, err := GenerateKeyExchange(shared.ECDH256)
	if nil != err {
		fmt.Println(err)
		os.Exit(1)
	}

	bPub := b.PublicKey()

	fmt.Println("B private key:\t", b)
	fmt.Println("B public key:\t", bPub)

	// end B

	// generate shared secret

	sharedSecretA, err := a.SharedSecret(bPub)
	if nil != err {
		fmt.Println(err)
		os.Exit(1)
	}

	sharedSecretB, err := b.SharedSecret(aPub)
	if nil != err {
		fmt.Println(err)
		os.Exit(1)
	}

	fmt.Println("shared secret for A:\t", base64.StdEncoding.EncodeToString(sharedSecretA))
	fmt.Println("shared secret for B:\t", base64.StdEncoding.EncodeToString(sharedSecretB))

	// end generate shared secret

}

func TestKXCurve25519Str(t *testing.T) {

	aStr := "ybAlYu1qLcRoiMZKDfuFy8yUTU2TxXRpoYY4xvCjmUfq"
	bStr := "yR0cwXiWjYYPP_MUPwzrZb8qOdEHBfR6RvrCTGEa4GLL"

	a, err := NewKXFromStr(aStr)
	if nil != err {
		fmt.Println(err)
		os.Exit(1)
	}
	fmt.Println("A private key type: ", a.KeyType())
	fmt.Println("A private key:\t", a)
	fmt.Println("A public key:\t", a.PublicKey())

	b, err := NewKXFromStr(bStr)
	if nil != err {
		fmt.Println(err)
		os.Exit(1)
	}
	fmt.Println("A private key type: ", b.KeyType())
	fmt.Println("B private key:\t", b)
	fmt.Println("B public key:\t", b.PublicKey())

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

}

func TestKXECDHStr(t *testing.T) {

	aStr := "0x7jZ3qC9cFxxTDIXtTDagJ8Ob0Sbv14KceWNaeXkRem"
	bStr := "01ZJoNmpMI1uL9g7deOd9SBnkjlkciN_hNzVS0JSLmkg"

	a, err := NewKXFromStr(aStr)
	if nil != err {
		fmt.Println(err)
		os.Exit(1)
	}
	fmt.Println("A private key type: ", a.KeyType())
	fmt.Println("A private key:\t", a)
	fmt.Println("A public key:\t", a.PublicKey())

	b, err := NewKXFromStr(bStr)
	if nil != err {
		fmt.Println(err)
		os.Exit(1)
	}
	fmt.Println("B private key type: ", b.KeyType())
	fmt.Println("B private key:\t", b)
	fmt.Println("B public key:\t", b.PublicKey())

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

}

func TestED25519JSON(t *testing.T) {

	k, err := NewKeyFromStr("{\"crv\":\"Ed25519\",\"d\":\"vUjQ3PaX8iqHA0Q58Wf7mN8h-oMgAE_cFQDfi0Sr2Js\",\"kty\":\"OKP\",\"x\":\"etHd2wg1POjqvQZ3yhiwwU2JRwCtcqzYQIOmp7BnnSo\"}")
	if nil != err {
		fmt.Println(err)
		os.Exit(1)
	}
	fmt.Println("JWK:", k)

	kb, err := json.Marshal(k)
	if nil != err {
		fmt.Println(err)
		os.Exit(1)
	}
	fmt.Println("JWK string:", string(kb))

}

func TestKXCurve25519JSON(t *testing.T) {

	aStr := "ybAlYu1qLcRoiMZKDfuFy8yUTU2TxXRpoYY4xvCjmUfq"

	a, err := NewKXFromStr(aStr)
	if nil != err {
		fmt.Println(err)
		os.Exit(1)
	}
	//fmt.Println("A private key type: ", a.KeyType())
	//fmt.Println("A private key:\t", a)
	//fmt.Println("A public key:\t", a.PublicKey())

	aBytes, err := json.Marshal(a)
	if nil != err {
		fmt.Println(err)
		os.Exit(1)
	}
	fmt.Println("KX:", string(aBytes))
}

/*
func TestRawKey(t *testing.T) {

	rawKey, err := ec.Generate(shared.ECDSA256)
	if nil != err {
		fmt.Println(err)
		os.Exit(1)
	}
	fmt.Println(rawKey.KeyType())

	k, err := NewFromRawKey(rawKey.PrivateKeyInstance())
	if nil != err {
		fmt.Println(err)
		os.Exit(1)
	}
	fmt.Println(k.KeyType())

}
*/

func TestKeyTypes(t *testing.T) {
	fmt.Println(ECDSA256)
	fmt.Println(CURVE25519)

	fmt.Println(GetKeyType(ECDSA384.String()))
	fmt.Println(GetKeyXType(CURVE25519.String()))
}
