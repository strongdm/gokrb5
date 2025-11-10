package spnego

import (
	"encoding/hex"
	"testing"

	"github.com/jcmturner/gokrb5/v8/gssapi"
	"github.com/jcmturner/gokrb5/v8/iana/msgtype"
	"github.com/jcmturner/gokrb5/v8/iana/nametype"
	"github.com/jcmturner/gokrb5/v8/messages"
	"github.com/jcmturner/gokrb5/v8/test/testdata"
	"github.com/jcmturner/gokrb5/v8/types"
	"github.com/stretchr/testify/assert"
)

func TestKRB5Token_NewTGTREQ(t *testing.T) {
	t.Parallel()
	sname := types.PrincipalName{
		NameType:   nametype.KRB_NT_SRV_INST,
		NameString: []string{"host", "test.example.com"},
	}
	realm := "TEST.EXAMPLE.COM"

	token, err := NewKRB5TokenTGTREQ(sname, realm)
	if err != nil {
		t.Fatalf("Error creating TGT_REQ token: %v", err)
	}

	assert.Equal(t, gssapi.OIDKRB5User2User.OID(), token.OID, "KRB5Token OID not as expected")
	assert.Equal(t, []byte{4, 0}, token.tokID, "TokID not as expected")
	assert.Equal(t, msgtype.KRB_TGT_REQ, token.TGTReq.MsgType, "TGT_REQ message type not as expected")
	assert.Equal(t, sname.NameString, token.TGTReq.ServerName.NameString, "ServerName not as expected")
	assert.Equal(t, realm, token.TGTReq.Realm, "Realm not as expected")
}

func TestKRB5Token_TGTREQMarshalUnmarshal(t *testing.T) {
	t.Parallel()
	sname := types.PrincipalName{
		NameType:   nametype.KRB_NT_SRV_INST,
		NameString: []string{"HTTP", "service.test.com"},
	}
	realm := "TEST.COM"

	// Create and marshal a TGT_REQ token
	token, err := NewKRB5TokenTGTREQ(sname, realm)
	if err != nil {
		t.Fatalf("Error creating TGT_REQ token: %v", err)
	}

	b, err := token.Marshal()
	if err != nil {
		t.Fatalf("Error marshalling TGT_REQ token: %v", err)
	}

	// Unmarshal the token
	var token2 KRB5Token
	err = token2.Unmarshal(b)
	if err != nil {
		t.Fatalf("Error unmarshalling TGT_REQ token: %v", err)
	}

	assert.Equal(t, token.OID, token2.OID, "OID mismatch after unmarshal")
	assert.Equal(t, token.tokID, token2.tokID, "tokID mismatch after unmarshal")
	assert.Equal(t, msgtype.KRB_TGT_REQ, token2.TGTReq.MsgType, "MsgType mismatch after unmarshal")
	assert.Equal(t, sname.NameString, token2.TGTReq.ServerName.NameString, "ServerName mismatch after unmarshal")
	assert.Equal(t, realm, token2.TGTReq.Realm, "Realm mismatch after unmarshal")
}

func TestKRB5Token_NewTGTREP(t *testing.T) {
	t.Parallel()
	// Create a simple ticket for testing
	ticket := messages.Ticket{
		TktVNO: 5,
		Realm:  testdata.TEST_REALM,
		SName: types.PrincipalName{
			NameType:   nametype.KRB_NT_SRV_INST,
			NameString: []string{"krbtgt", testdata.TEST_REALM},
		},
	}

	sname := types.PrincipalName{
		NameType:   nametype.KRB_NT_SRV_INST,
		NameString: []string{"krbtgt", testdata.TEST_REALM},
	}

	token, err := NewKRB5TokenTGTREP(ticket, sname)
	if err != nil {
		t.Fatalf("Error creating TGT_REP token: %v", err)
	}

	assert.Equal(t, gssapi.OIDKRB5User2User.OID(), token.OID, "KRB5Token OID not as expected")
	assert.Equal(t, []byte{4, 1}, token.tokID, "TokID not as expected")
	assert.Equal(t, msgtype.KRB_TGT_REP, token.TGTRep.MsgType, "TGT_REP message type not as expected")
	assert.Equal(t, sname.NameString, token.TGTRep.ServerName.NameString, "ServerName not as expected")
	assert.Equal(t, 5, token.TGTRep.Ticket.TktVNO, "Ticket version not as expected")
}

func TestKRB5Token_IsTGTReq(t *testing.T) {
	t.Parallel()
	sname := types.PrincipalName{
		NameType:   nametype.KRB_NT_SRV_INST,
		NameString: []string{"host", "test.example.com"},
	}

	token, err := NewKRB5TokenTGTREQ(sname, "TEST.COM")
	if err != nil {
		t.Fatalf("Error creating TGT_REQ token: %v", err)
	}

	assert.True(t, token.IsTGTReq(), "IsTGTReq should return true for TGT_REQ token")
	assert.False(t, token.IsTGTRep(), "IsTGTRep should return false for TGT_REQ token")
	assert.False(t, token.IsAPReq(), "IsAPReq should return false for TGT_REQ token")
	assert.False(t, token.IsAPRep(), "IsAPRep should return false for TGT_REQ token")
	assert.False(t, token.IsKRBError(), "IsKRBError should return false for TGT_REQ token")
}

func TestKRB5Token_IsTGTRep(t *testing.T) {
	t.Parallel()
	ticket := messages.Ticket{
		TktVNO: 5,
		Realm:  testdata.TEST_REALM,
		SName: types.PrincipalName{
			NameType:   nametype.KRB_NT_SRV_INST,
			NameString: []string{"krbtgt", testdata.TEST_REALM},
		},
	}
	sname := types.PrincipalName{
		NameType:   nametype.KRB_NT_SRV_INST,
		NameString: []string{"krbtgt", testdata.TEST_REALM},
	}

	token, err := NewKRB5TokenTGTREP(ticket, sname)
	if err != nil {
		t.Fatalf("Error creating TGT_REP token: %v", err)
	}

	assert.True(t, token.IsTGTRep(), "IsTGTRep should return true for TGT_REP token")
	assert.False(t, token.IsTGTReq(), "IsTGTReq should return false for TGT_REP token")
	assert.False(t, token.IsAPReq(), "IsAPReq should return false for TGT_REP token")
	assert.False(t, token.IsAPRep(), "IsAPRep should return false for TGT_REP token")
	assert.False(t, token.IsKRBError(), "IsKRBError should return false for TGT_REP token")
}

func TestKRB5Token_TGTREQVerify(t *testing.T) {
	t.Parallel()
	sname := types.PrincipalName{
		NameType:   nametype.KRB_NT_SRV_INST,
		NameString: []string{"host", "test.example.com"},
	}

	token, err := NewKRB5TokenTGTREQ(sname, "TEST.COM")
	if err != nil {
		t.Fatalf("Error creating TGT_REQ token: %v", err)
	}

	ok, status := token.Verify()
	assert.True(t, ok, "TGT_REQ token should verify successfully")
	assert.Equal(t, gssapi.StatusComplete, status.Code, "Status code should be StatusComplete")
}

func TestKRB5Token_TGTREPVerify(t *testing.T) {
	t.Parallel()
	ticket := messages.Ticket{
		TktVNO: 5,
		Realm:  testdata.TEST_REALM,
		SName: types.PrincipalName{
			NameType:   nametype.KRB_NT_SRV_INST,
			NameString: []string{"krbtgt", testdata.TEST_REALM},
		},
	}
	sname := types.PrincipalName{
		NameType:   nametype.KRB_NT_SRV_INST,
		NameString: []string{"krbtgt", testdata.TEST_REALM},
	}

	token, err := NewKRB5TokenTGTREP(ticket, sname)
	if err != nil {
		t.Fatalf("Error creating TGT_REP token: %v", err)
	}

	ok, status := token.Verify()
	assert.True(t, ok, "TGT_REP token should verify successfully")
	assert.Equal(t, gssapi.StatusComplete, status.Code, "Status code should be StatusComplete")
}

func TestKRB5Token_TGTREQTokenIDBytes(t *testing.T) {
	t.Parallel()
	expectedTokenID := []byte{4, 0}
	tokenID, _ := hex.DecodeString(TOK_ID_KRB_TGT_REQ)
	assert.Equal(t, expectedTokenID, tokenID, "TGT_REQ token ID bytes not as expected")
}

func TestKRB5Token_TGTREPTokenIDBytes(t *testing.T) {
	t.Parallel()
	expectedTokenID := []byte{4, 1}
	tokenID, _ := hex.DecodeString(TOK_ID_KRB_TGT_REP)
	assert.Equal(t, expectedTokenID, tokenID, "TGT_REP token ID bytes not as expected")
}
