//go:build examples
// +build examples

package main

import (
	"encoding/base64"
	"fmt"
	"log"

	"github.com/jcmturner/gofork/encoding/asn1"
	"github.com/jcmturner/gokrb5/v8/gssapi"
	"github.com/jcmturner/gokrb5/v8/iana/nametype"
	"github.com/jcmturner/gokrb5/v8/spnego"
	"github.com/jcmturner/gokrb5/v8/types"
)

// This example demonstrates how to create a SPNEGO token containing a KRB5 TGT-REQ token
// for User-to-User authentication. This is used in the initial phase of U2U authentication
// where the client requests the server's TGT.
//
// Per draft-swift-win2k-krb-user2user-03, the User-to-User authentication flow is:
// 1. Client sends TGT-REQ to server (this example)
// 2. Server responds with TGT-REP containing its TGT
// 3. Client uses server's TGT to request a U2U service ticket from KDC
// 4. Client sends AP-REQ with APOptionUseSessionKey to server
func main() {
	// Create a principal name for the server whose TGT we want to obtain
	// This would typically be the service we want to authenticate to
	serverName := types.PrincipalName{
		NameType:   nametype.KRB_NT_SRV_INST,
		NameString: []string{"HTTP", "service.example.com"},
	}
	realm := "EXAMPLE.COM"

	// Step 1: Create a KRB5 TGT-REQ token
	// This requests the server's TGT for User-to-User authentication
	krb5Token, err := spnego.NewKRB5TokenTGTREQ(serverName, realm)
	if err != nil {
		log.Fatalf("Failed to create KRB5 TGT-REQ token: %v", err)
	}

	// Marshal the KRB5 token to bytes
	krb5TokenBytes, err := krb5Token.Marshal()
	if err != nil {
		log.Fatalf("Failed to marshal KRB5 token: %v", err)
	}

	// Step 2: Create a NegTokenInit containing the KRB5 TGT-REQ token
	// NegTokenInit is the initial SPNEGO negotiation token
	negTokenInit := spnego.NegTokenInit{
		MechTypes: []asn1.ObjectIdentifier{
			gssapi.OIDMSLegacyKRB5.OID(), // MS Legacy Kerberos 5 OID
			gssapi.OIDKRB5.OID(),         // Standard Kerberos 5 OID
		},
		MechTokenBytes: krb5TokenBytes,
	}

	// Step 3: Create a SPNEGO token wrapping the NegTokenInit
	spnegoToken := spnego.SPNEGOToken{
		Init:         true,
		NegTokenInit: negTokenInit,
	}

	// Marshal the complete SPNEGO token
	spnegoTokenBytes, err := spnegoToken.Marshal()
	if err != nil {
		log.Fatalf("Failed to marshal SPNEGO token: %v", err)
	}

	// Step 4: Encode for HTTP Authorization header (optional)
	// In practice, this would be sent in an HTTP Authorization header
	encodedToken := base64.StdEncoding.EncodeToString(spnegoTokenBytes)
	fmt.Printf("Authorization: Negotiate %s\n", encodedToken)

	// Step 5: Demonstrate unmarshaling to verify correctness
	var verifyToken spnego.SPNEGOToken
	err = verifyToken.Unmarshal(spnegoTokenBytes)
	if err != nil {
		log.Fatalf("Failed to unmarshal SPNEGO token: %v", err)
	}

	// Verify the KRB5 token within
	var verifyKrb5Token spnego.KRB5Token
	err = verifyKrb5Token.Unmarshal(verifyToken.NegTokenInit.MechTokenBytes)
	if err != nil {
		log.Fatalf("Failed to unmarshal KRB5 token from SPNEGO: %v", err)
	}

	if !verifyKrb5Token.IsTGTReq() || !verifyKrb5Token.OID.Equal(gssapi.OIDKRB5User2User.OID()) {
		log.Fatalf("Token verification failed")
	}

	fmt.Println("Token created and verified successfully!")
}
