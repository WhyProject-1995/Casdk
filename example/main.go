package main

import (
	"fmt"
	"os"

	"github.com/w862456671/Casdk"
)

func main() {
	//	var idresp Casdk.CAGetIdentityResponse
	var idsresp Casdk.CAListAllIdentitesResponse
	//初始化CAClient
	err := Casdk.InitCASDK("./", "caconfig.yaml")
	if err != nil {
		fmt.Println(err)
	}
	//注册admin证书
	enrollRequest := Casdk.CaEnrollmentRequest{EnrollmentId: "admin", Secret: "adminpw"}
	_, _, err = Casdk.Enroll(Casdk.CA, enrollRequest)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	//注册peer证书
	//	attr := []Casdk.CaRegisterAttribute{{
	//		Name: "Revoker",
	//		Value: "true",
	//		ECert: true,
	//	},
	//	}
	//	rr := Casdk.CARegistrationRequest{
	//		EnrolmentId: "peer2",
	//		Affiliation: "org1.department1",
	//		Type: "peer",
	//		Attrs: attr,
	//	}
	//	err = Casdk.Register(Casdk.CA, Casdk.ID, &rr)
	//
	//	if err != nil {
	//		fmt.Println(err)
	//	}
	//撤销证书
	//	req := Casdk.CARevocationRequest{EnrollmentId: "peer1", Reason: "aacompromise", GenCRL: true}
	//	Casdk.Revoke(Casdk.CA, Casdk.ID, &req)
	//查询单一id
	//	idresp, err = Casdk.GetIndentity(Casdk.CA, Casdk.ID, "peer1", "ca1")
	//	if err != nil {
	//		fmt.Println(err)
	//	}
	//	fmt.Println(idresp)
	//查询所有id
	idsresp, err = Casdk.GetIndentities(Casdk.CA, Casdk.ID)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(idsresp)
}
