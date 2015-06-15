package pkcs12

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/x509/pkix"
	"encoding/asn1"
	"hash"
)

type macData struct {
	Mac        digestInfo
	MacSalt    []byte
	Iterations int `asn1:"optional,default:1"`
}

// from PKCS#7:
type digestInfo struct {
	Algorithm pkix.AlgorithmIdentifier
	Digest    []byte
}

const (
	sha1Algorithm = "SHA-1"
)

var (
	oidSha1Algorithm = asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}
	hashNameByID     = map[string]string{
		oidSha1Algorithm.String(): sha1Algorithm,
	}
	hashByName = map[string]func() hash.Hash{
		sha1Algorithm: sha1.New,
	}
)

func verifyMac(macData *macData, message, password []byte) error {
	name, ok := hashNameByID[macData.Mac.Algorithm.Algorithm.String()]
	if !ok {
		return NotImplementedError("unknown digest algorithm: " + macData.Mac.Algorithm.Algorithm.String())
	}
	k := deriveMacKeyByAlg[name](macData.MacSalt, password, macData.Iterations)
	password = nil

	mac := hmac.New(hashByName[name], k)
	mac.Write(message)
	expectedMAC := mac.Sum(nil)

	if !hmac.Equal(macData.Mac.Digest, expectedMAC) {
		return ErrIncorrectPassword
	}
	return nil
}
