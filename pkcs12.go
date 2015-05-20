// Package pkcs12 provides some implementations of PKCS#12.
//
// This implementation is distilled from https://tools.ietf.org/html/rfc7292 and referenced documents.
// It is intended for decoding P12/PFX-stored certificate+key for use with the crypto/tls package.
package pkcs12

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
)

type pfxPdu struct {
	Version  int
	AuthSafe contentInfo
	MacData  macData `asn1:"optional"`
}

type contentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"tag:0,explicit,optional"`
}

const (
	oidDataContentType          = "1.2.840.113549.1.7.1"
	oidEncryptedDataContentType = "1.2.840.113549.1.7.6"
)

type encryptedData struct {
	Version              int
	EncryptedContentInfo encryptedContentInfo
}

type encryptedContentInfo struct {
	ContentType                asn1.ObjectIdentifier
	ContentEncryptionAlgorithm pkix.AlgorithmIdentifier
	EncryptedContent           []byte `asn1:"tag:0,optional"`
}

func (i encryptedContentInfo) GetAlgorithm() pkix.AlgorithmIdentifier {
	return i.ContentEncryptionAlgorithm
}
func (i encryptedContentInfo) GetData() []byte { return i.EncryptedContent }

type safeBag struct {
	ID         asn1.ObjectIdentifier
	Value      asn1.RawValue     `asn1:"tag:0,explicit"`
	Attributes []pkcs12Attribute `asn1:"set,optional"`
}

type pkcs12Attribute struct {
	ID    asn1.ObjectIdentifier
	Value asn1.RawValue `ans1:"set"`
}

type encryptedPrivateKeyInfo struct {
	AlgorithmIdentifier pkix.AlgorithmIdentifier
	EncryptedData       []byte
}

func (i encryptedPrivateKeyInfo) GetAlgorithm() pkix.AlgorithmIdentifier { return i.AlgorithmIdentifier }
func (i encryptedPrivateKeyInfo) GetData() []byte                        { return i.EncryptedData }

// PEM block types
const (
	CertificateType = "CERTIFICATE"
	PrivateKeyType  = "PRIVATE KEY"
)

// ConvertToPEM converts all "safe bags" contained in pfxData to PEM blocks.
func ConvertToPEM(pfxData, utf8Password []byte) (blocks []*pem.Block, err error) {
	p, err := bmpString(utf8Password)

	for i := 0; i < len(utf8Password); i++ {
		utf8Password[i] = 0
	}

	if err != nil {
		return nil, ErrIncorrectPassword
	}

	bags, p, err := getSafeContents(pfxData, p)

	blocks = make([]*pem.Block, 0, 2)
	for _, bag := range bags {
		var block *pem.Block
		block, err = convertBag(&bag, p)
		if err != nil {
			return
		}
		blocks = append(blocks, block)
	}

	return
}

func convertBag(bag *safeBag, password []byte) (*pem.Block, error) {
	b := new(pem.Block)

	for _, attribute := range bag.Attributes {
		k, v, err := convertAttribute(&attribute)
		if err != nil {
			return nil, err
		}
		if b.Headers == nil {
			b.Headers = make(map[string]string)
		}
		b.Headers[k] = v
	}

	bagType := bagTypeNameByOID[bag.ID.String()]
	switch bagType {
	case certBagType:
		b.Type = CertificateType
		certsData, err := decodeCertBag(bag.Value.Bytes)
		if err != nil {
			return nil, err
		}
		b.Bytes = certsData
	case pkcs8ShroudedKeyBagType:
		b.Type = PrivateKeyType

		key, err := decodePkcs8ShroudedKeyBag(bag.Value.Bytes, password)
		if err != nil {
			return nil, err
		}

		switch key := key.(type) {
		case *rsa.PrivateKey:
			b.Bytes = x509.MarshalPKCS1PrivateKey(key)
		case *ecdsa.PrivateKey:
			b.Bytes, err = x509.MarshalECPrivateKey(key)
			if err != nil {
				return nil, err
			}
		default:
			return nil, errors.New("found unknown private key type in PKCS#8 wrapping")
		}
	default:
		return nil, errors.New("don't know how to convert a safe bag of type " + bag.ID.String())
	}
	return b, nil
}

const (
	oidFriendlyName     = "1.2.840.113549.1.9.20"
	oidLocalKeyID       = "1.2.840.113549.1.9.21"
	oidMicrosoftCSPName = "1.3.6.1.4.1.311.17.1"
)

var attributeNameByOID = map[string]string{
	oidFriendlyName:     "friendlyName",
	oidLocalKeyID:       "localKeyId",
	oidMicrosoftCSPName: "Microsoft CSP Name", // openssl-compatible
}

func convertAttribute(attribute *pkcs12Attribute) (key, value string, err error) {
	oid := attribute.ID.String()
	key = attributeNameByOID[oid]
	switch oid {
	case oidMicrosoftCSPName:
		fallthrough
	case oidFriendlyName:
		if _, err = asn1.Unmarshal(attribute.Value.Bytes, &attribute.Value); err != nil {
			return
		}
		if value, err = decodeBMPString(attribute.Value.Bytes); err != nil {
			return
		}
	case oidLocalKeyID:
		id := new([]byte)
		if _, err = asn1.Unmarshal(attribute.Value.Bytes, id); err != nil {
			return
		}
		value = fmt.Sprintf("% x", *id)
	default:
		err = errors.New("don't know how to handle attribute with OID " + attribute.ID.String())
		return
	}

	return key, value, nil
}

// Decode extracts a certificate and private key from pfxData.
// This function assumes that there is only one certificate and only one private key in the pfxData.
func Decode(pfxData, utf8Password []byte) (privateKey interface{}, certificate *x509.Certificate, err error) {
	p, err := bmpString(utf8Password)

	for i := 0; i < len(utf8Password); i++ {
		utf8Password[i] = 0
	}

	if err != nil {
		return nil, nil, err
	}
	bags, p, err := getSafeContents(pfxData, p)
	if err != nil {
		return nil, nil, err
	}

	if len(bags) != 2 {
		err = errors.New("expected exactly two safe bags in the PFX PDU")
		return
	}

	for _, bag := range bags {
		bagType := bagTypeNameByOID[bag.ID.String()]

		switch bagType {
		case certBagType:
			certsData, err := decodeCertBag(bag.Value.Bytes)
			if err != nil {
				return nil, nil, err
			}
			certs, err := x509.ParseCertificates(certsData)
			if err != nil {
				return nil, nil, err
			}
			if len(certs) != 1 {
				err = errors.New("expected exactly one certificate in the certBag")
				return nil, nil, err
			}
			certificate = certs[0]
		case pkcs8ShroudedKeyBagType:
			if privateKey, err = decodePkcs8ShroudedKeyBag(bag.Value.Bytes, p); err != nil {
				return nil, nil, err
			}
		}
	}

	if certificate == nil {
		return nil, nil, errors.New("certificate missing")
	}
	if privateKey == nil {
		return nil, nil, errors.New("private key missing")
	}

	return
}

func getSafeContents(p12Data, password []byte) (bags []safeBag, actualPassword []byte, err error) {
	pfx := new(pfxPdu)
	if _, err = asn1.Unmarshal(p12Data, pfx); err != nil {
		return nil, nil, fmt.Errorf("error reading P12 data: %v", err)
	}

	if pfx.Version != 3 {
		return nil, nil, NotImplementedError("can only decode v3 PFX PDU's")
	}

	if pfx.AuthSafe.ContentType.String() != oidDataContentType {
		return nil, nil, NotImplementedError("only password-protected PFX is implemented")
	}

	// unmarshal the explicit bytes in the content for type 'data'
	if _, err = asn1.Unmarshal(pfx.AuthSafe.Content.Bytes, &pfx.AuthSafe.Content); err != nil {
		return nil, nil, err
	}

	actualPassword = password
	password = nil
	if len(pfx.MacData.Mac.Algorithm.Algorithm) > 0 {
		if err = verifyMac(&pfx.MacData, pfx.AuthSafe.Content.Bytes, actualPassword); err != nil {
			if err == ErrIncorrectPassword && bytes.Compare(actualPassword, []byte{0, 0}) == 0 {
				// some implementations use an empty byte array for the empty string password
				// try one more time with empty-empty password
				actualPassword = []byte{}
				err = verifyMac(&pfx.MacData, pfx.AuthSafe.Content.Bytes, actualPassword)
			}
		}
		if err != nil {
			return
		}
	}

	var authenticatedSafe []contentInfo
	if _, err = asn1.Unmarshal(pfx.AuthSafe.Content.Bytes, &authenticatedSafe); err != nil {
		return
	}

	if len(authenticatedSafe) != 2 {
		return nil, nil, NotImplementedError("expected exactly two items in the authenticated safe")
	}

	for _, ci := range authenticatedSafe {
		var data []byte
		switch ci.ContentType.String() {
		case oidDataContentType:
			if _, err = asn1.Unmarshal(ci.Content.Bytes, &data); err != nil {
				return
			}
		case oidEncryptedDataContentType:
			var encryptedData encryptedData
			if _, err = asn1.Unmarshal(ci.Content.Bytes, &encryptedData); err != nil {
				return
			}
			if encryptedData.Version != 0 {
				return nil, nil, NotImplementedError("only version 0 of EncryptedData is supported")
			}
			if data, err = pbDecrypt(encryptedData.EncryptedContentInfo, actualPassword); err != nil {
				return
			}
		default:
			return nil, nil, NotImplementedError("only data and encryptedData content types are supported in authenticated safe")
		}

		var safeContents []safeBag
		if _, err = asn1.Unmarshal(data, &safeContents); err != nil {
			return
		}
		bags = append(bags, safeContents...)
	}
	return
}
