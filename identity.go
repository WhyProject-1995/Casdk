package Casdk

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"io/ioutil"
	"os"
	"path"
)

type Identity struct {
	Certificate *x509.Certificate
	PrivateKey  interface{}
	MspId       string
}

var ID *Identity

/*func (i *Identity) MarshalIndentity() error {
	var pk, cert string

	switch i.PrivateKey.(type) {
	case *ecdsa.PrivateKey:
		cast := i.PrivateKey.(*ecdsa.PrivateKey)
		b, err := x509.MarshalECPrivateKey(cast)
		if err != nil {
			return err
		}
		block := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: b})
		pk = base64.RawStdEncoding.EncodeToString(block)
	default:
		return ErrInvalidKeyType
	}

	cert = base64.RawStdEncoding.EncodeToString(i.Certificate.Raw)
	i.CetMap = make(map[string]string)
	i.CetMap["cert"] = cert
	i.CetMap["pk"] = pk
	i.CetMap["mspid"] = i.MspId
//	str, err := json.Marshal(map[string]string{"cert":cert, "pk":pk, "mspid":i.MspId})
//	if err != nil {
//		return "", err
//	}
//	return string(str), nil
	return nil
}*/

func (i *Identity) SaveCert(ca *FabricCAClient, enreq *CaEnrollmentRequest, cainfo *CAGetCertResponse) error {
	var mspDir string
	var err error

	is, err := IsPathExists(ca.FilePath)
	if err != nil || !is {
		return err
	}
	//保存tls证书
	//	if enreq.Profile == "tls" {
	//		err = saveTLScert(ca, i, cainfo)
	//		if err != nil {
	//			return err
	//		}
	//		return nil
	//	}

	if enreq == nil {
		mspDir = path.Join(ca.FilePath, "/msp")
	} else {
		mspfile := enreq.EnrollmentId + "msp"
		mspDir = path.Join(ca.FilePath, mspfile)
	}
	//保存根证书
	caPath := path.Join(mspDir, "/cacerts")
	err = os.MkdirAll(caPath, os.ModePerm)
	if err != nil {
		return err
	}
	caFile := path.Join(caPath, "ca-cert.pem")
	ca_pem := pem.EncodeToMemory(
		&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cainfo.RootCertificates[0].Raw,
		},
	)
	err = ioutil.WriteFile(caFile, ca_pem, 0644)
	if err != nil {
		return err
	}
	//保存中间证书
	if len(cainfo.IntermediateCertificates) > 0 {
		intercaPath := path.Join(mspDir, "/intermediatecerts")
		err = os.MkdirAll(intercaPath, os.ModePerm)
		if err != nil {
			return err
		}
		caFile = path.Join(intercaPath, "intermediate-certs.pem")
		for _, interca := range cainfo.IntermediateCertificates {
			interca_pem := pem.EncodeToMemory(interca)
			fd, err := os.OpenFile(caFile, os.O_RDWR|os.O_CREATE|os.O_APPEND, os.ModePerm)
			if err != nil {
				return err
			}
			fd.Write(interca_pem)
			fd.Write([]byte("\n"))
			fd.Close()
		}
	}
	//保存证书
	certPath := path.Join(mspDir + "/signcerts")
	err = os.MkdirAll(certPath, os.ModePerm)
	if err != nil {
		return err
	}
	certFile := path.Join(certPath, "cert.pem")
	cert_pem := pem.EncodeToMemory(
		&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: i.Certificate.Raw,
		},
	)
	err = ioutil.WriteFile(certFile, cert_pem, 0644)
	if err != nil {
		return err
	}
	//保存私钥
	keyPath := path.Join(mspDir, "/keystore")
	err = os.MkdirAll(keyPath, os.ModePerm)
	if err != nil {
		return err
	}
	keyFile := path.Join(keyPath, "key.pem")
	key_byte, err := x509.MarshalECPrivateKey(i.PrivateKey.(*ecdsa.PrivateKey))
	if err != nil {
		return err
	}
	key_pem := pem.EncodeToMemory(
		&pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: key_byte,
		},
	)
	err = ioutil.WriteFile(keyFile, key_pem, 0644)
	if err != nil {
		return nil
	}
	return nil
}

//保存crl
func SaveCrl(ca *FabricCAClient, request *CARevocationRequest, result *CARevokeResult) error {
	var err error
	mspfile := request.EnrollmentId + "msp"
	mspDir := path.Join(ca.FilePath, mspfile)
	crlPath := path.Join(mspDir, "/crls")
	err = os.MkdirAll(crlPath, os.ModePerm)
	if err != nil {
		return err
	}
	crlFile := path.Join(crlPath, "crl.pem")

	crl, err := base64.StdEncoding.DecodeString(result.CRL)
	if err != nil {
		return err
	}
	crl_pem := pem.EncodeToMemory(
		&pem.Block{
			Type:  "X509 CRL",
			Bytes: crl,
		},
	)
	err = ioutil.WriteFile(crlFile, crl_pem, 0644)
	if err != nil {
		return err
	}
	return nil
}

func (i *Identity) SaveTLScert(ca *FabricCAClient, cainfo *CAGetCertResponse) error {
	var err error
	mspDir := path.Join(ca.FilePath, "/tlsmsp")

	//保存根证书
	caPath := path.Join(mspDir, "/tlscacerts")
	err = os.MkdirAll(caPath, os.ModePerm)
	if err != nil {
		return err
	}
	caFile := path.Join(caPath, "ca-cert.pem")
	ca_pem := pem.EncodeToMemory(
		&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cainfo.RootCertificates[0].Raw,
		},
	)
	err = ioutil.WriteFile(caFile, ca_pem, 0644)
	if err != nil {
		return err
	}
	//保存中间证书
	if len(cainfo.IntermediateCertificates) > 0 {
		intercaPath := path.Join(mspDir, "/tlsintermediatecerts")
		err = os.MkdirAll(intercaPath, os.ModePerm)
		if err != nil {
			return err
		}
		caFile = path.Join(intercaPath, "intermediate-certs.pem")
		for _, interca := range cainfo.IntermediateCertificates {
			interca_pem := pem.EncodeToMemory(interca)
			fd, err := os.OpenFile(caFile, os.O_RDWR|os.O_CREATE|os.O_APPEND, os.ModePerm)
			if err != nil {
				return err
			}
			fd.Write(interca_pem)
			fd.Write([]byte("\n"))
			fd.Close()
		}
	}
	//保存证书
	certPath := path.Join(mspDir + "/signcerts")
	err = os.MkdirAll(certPath, os.ModePerm)
	if err != nil {
		return err
	}
	certFile := path.Join(certPath, "cert.pem")
	cert_pem := pem.EncodeToMemory(
		&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: i.Certificate.Raw,
		},
	)
	err = ioutil.WriteFile(certFile, cert_pem, 0644)
	if err != nil {
		return err
	}
	//保存私钥
	keyPath := path.Join(mspDir, "/keystore")
	err = os.MkdirAll(keyPath, os.ModePerm)
	if err != nil {
		return err
	}
	keyFile := path.Join(keyPath, "key.pem")
	key_byte, err := x509.MarshalECPrivateKey(i.PrivateKey.(*ecdsa.PrivateKey))
	if err != nil {
		return err
	}
	key_pem := pem.EncodeToMemory(
		&pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: key_byte,
		},
	)
	err = ioutil.WriteFile(keyFile, key_pem, 0644)
	if err != nil {
		return nil
	}
	return nil
}
