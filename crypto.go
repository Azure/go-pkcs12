// implementation of https://tools.ietf.org/html/rfc2898#section-6.1.2

package pkcs12

import (
	"bytes"
	"crypto/cipher"
	"crypto/des"
	"crypto/x509/pkix"
	"encoding/asn1"

	"github.com/dgryski/go-rc2"
)

const (
	pbeWithSHAAnd3KeyTripleDESCBC = "pbeWithSHAAnd3-KeyTripleDES-CBC"
	pbewithSHAAnd40BitRC2CBC      = "pbewithSHAAnd40BitRC2-CBC"
)

var algByOID = map[string]string{
	"1.2.840.113549.1.12.1.3": pbeWithSHAAnd3KeyTripleDESCBC,
	"1.2.840.113549.1.12.1.6": pbewithSHAAnd40BitRC2CBC,
}

var blockcodeByAlg = map[string]func(key []byte) (cipher.Block, error){
	pbeWithSHAAnd3KeyTripleDESCBC: des.NewTripleDESCipher,
	pbewithSHAAnd40BitRC2CBC: func(key []byte) (cipher.Block, error) {
		return rc2.New(key, len(key)*8)
	},
}

type pbeParams struct {
	Salt       []byte
	Iterations int
}

func pbDecrypterFor(algorithm pkix.AlgorithmIdentifier, password []byte) (cipher.BlockMode, error) {
	algorithmName, supported := algByOID[algorithm.Algorithm.String()]
	if !supported {
		return nil, NotImplementedError("algorithm " + algorithm.Algorithm.String() + " is not supported")
	}

	var params pbeParams
	if _, err := asn1.Unmarshal(algorithm.Parameters.FullBytes, &params); err != nil {
		return nil, err
	}

	k := deriveKeyByAlg[algorithmName](params.Salt, password, params.Iterations)
	iv := deriveIVByAlg[algorithmName](params.Salt, password, params.Iterations)
	password = nil

	code, err := blockcodeByAlg[algorithmName](k)
	if err != nil {
		return nil, err
	}

	cbc := cipher.NewCBCDecrypter(code, iv)
	return cbc, nil
}

func pbDecrypt(info decryptable, password []byte) (decrypted []byte, err error) {
	cbc, err := pbDecrypterFor(info.GetAlgorithm(), password)
	password = nil
	if err != nil {
		return nil, err
	}

	encrypted := info.GetData()

	decrypted = make([]byte, len(encrypted))
	cbc.CryptBlocks(decrypted, encrypted)

	if psLen := int(decrypted[len(decrypted)-1]); psLen > 0 && psLen < 9 {
		m := decrypted[:len(decrypted)-psLen]
		ps := decrypted[len(decrypted)-psLen:]
		if bytes.Compare(ps, bytes.Repeat([]byte{byte(psLen)}, psLen)) != 0 {
			return nil, ErrDecryption
		}
		decrypted = m
	} else {
		return nil, ErrDecryption
	}

	return
}

type decryptable interface {
	GetAlgorithm() pkix.AlgorithmIdentifier
	GetData() []byte
}
