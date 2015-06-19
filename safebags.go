package pkcs12

import (
	"crypto/x509"
	"encoding/asn1"
	"fmt"
)

//see https://tools.ietf.org/html/rfc7292#appendix-D
var (
	oidKeyBagType              = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 10, 1, 1}
	oidPkcs8ShroudedKeyBagType = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 10, 1, 2}
	oidCertBagType             = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 10, 1, 3}
	oidCrlBagType              = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 10, 1, 4}
	oidSecretBagType           = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 10, 1, 5}
	oidSafeContentsBagType     = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 10, 1, 6}
)

var (
	oidCertTypeX509Certificate = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 22, 1}
	oidLocalKeyIDAttribute     = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 21}
)

type certBag struct {
	ID   asn1.ObjectIdentifier
	Data []byte `asn1:"tag:0,explicit"`
}

func decodePkcs8ShroudedKeyBag(asn1Data, password []byte) (privateKey interface{}, err error) {
	pkinfo := new(encryptedPrivateKeyInfo)
	if _, err = asn1.Unmarshal(asn1Data, pkinfo); err != nil {
		err = fmt.Errorf("error decoding PKCS8 shrouded key bag: %v", err)
		return nil, err
	}

	pkData, err := pbDecrypt(pkinfo, password)
	if err != nil {
		err = fmt.Errorf("error decrypting PKCS8 shrouded key bag: %v", err)
		return
	}

	rv := new(asn1.RawValue)
	if _, err = asn1.Unmarshal(pkData, rv); err != nil {
		err = fmt.Errorf("could not decode decrypted private key data")
	}

	if privateKey, err = x509.ParsePKCS8PrivateKey(pkData); err != nil {
		err = fmt.Errorf("error parsing PKCS8 private key: %v", err)
		return nil, err
	}
	return
}

func decodeCertBag(asn1Data []byte) (x509Certificates []byte, err error) {
	bag := new(certBag)
	if _, err := asn1.Unmarshal(asn1Data, bag); err != nil {
		err = fmt.Errorf("error decoding cert bag: %v", err)
		return nil, err
	}
	if !bag.ID.Equal(oidCertTypeX509Certificate) {
		return nil, NotImplementedError("only X509 certificates are supported")
	}
	return bag.Data, nil
}
