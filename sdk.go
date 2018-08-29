package Casdk

import (
	"path"
	)

func InitCASDK(configPth string, configFile string) error {
	caconfigFilePath := path.Join(configPth, configFile)
	_, err := NewCAClient(caconfigFilePath, nil)
	if err != nil {
		return err
	}
	return nil
}

func Enroll(ca *FabricCAClient, req CaEnrollmentRequest) (*Identity, []byte, error) {
	id, csr, err := ca.Enroll(req)
	if err != nil {
		return nil, nil, err
	}
	resp, err := getCaCerts(ca)
	if req.Profile == "tls" {
		id.SaveTLScert(ca, resp)
	} else {
		id.SaveCert(ca, nil, resp)
	}
	return id, csr, nil
}

func Register(ca *FabricCAClient, identity *Identity, req *CARegistrationRequest) error {

	resp, err := ca.Register(identity, req)
	if err != nil {
		return err
	}

	enrollRequest := CaEnrollmentRequest{EnrollmentId: req.EnrolmentId, Secret: resp}
	id, _, err := ca.Enroll(enrollRequest)
	if err != nil {
		return err
	}

	cainfo, err := getCaCerts(ca)
	if err != nil {
		return err
	}
	err = id.SaveCert(ca, &enrollRequest, cainfo)
	if err != nil {
		return err
	}
	return nil
}

func getCaCerts(ca *FabricCAClient) (*CAGetCertResponse, error) {
	resp, err := ca.GetCaCertificateChain(ca.ServerInfo.CAName)
	if err != nil {
		return nil, err
	}

	return resp, nil
}

func Revoke(ca *FabricCAClient, identity *Identity, req *CARevocationRequest) error {
	r, err := ca.Revoke(identity, req)
	if err != nil {
		return err
	}
	err = SaveCrl(ca, req, r)
	if err != nil {
		return err
	}
	return nil
}

func GetIndentity(ca *FabricCAClient, identity *Identity, id string, caName string) (CAGetIdentityResponse, error) {
	resp, err := ca.GetIndentity(identity, id, caName)
	if err != nil {
		return CAGetIdentityResponse{}, err
	}

	return *resp, nil
}

func GetIndentities(ca *FabricCAClient, identity *Identity) (CAListAllIdentitesResponse, error) {
	resp, err := ca.GetIdentities(identity, "")
	if err != nil {
		return CAListAllIdentitesResponse{}, nil
	}

	return *resp, nil
}