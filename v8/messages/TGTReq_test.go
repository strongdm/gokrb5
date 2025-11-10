package messages

import (
	"testing"

	"github.com/jcmturner/gokrb5/v8/iana"
	"github.com/jcmturner/gokrb5/v8/iana/msgtype"
	"github.com/jcmturner/gokrb5/v8/iana/nametype"
	"github.com/jcmturner/gokrb5/v8/types"
	"github.com/stretchr/testify/assert"
)

func TestTGTReq_New(t *testing.T) {
	t.Parallel()
	sname := types.PrincipalName{
		NameType:   nametype.KRB_NT_SRV_INST,
		NameString: []string{"HTTP", "service.example.com"},
	}
	realm := "EXAMPLE.COM"

	tgtReq := NewTGTReq(sname, realm)

	assert.Equal(t, iana.PVNO, tgtReq.PVNO, "PVNO not as expected")
	assert.Equal(t, msgtype.KRB_TGT_REQ, tgtReq.MsgType, "MsgType not as expected")
	assert.Equal(t, sname.NameString, tgtReq.ServerName.NameString, "ServerName not as expected")
	assert.Equal(t, realm, tgtReq.Realm, "Realm not as expected")
}

func TestTGTReq_MarshalUnmarshal(t *testing.T) {
	t.Parallel()
	sname := types.PrincipalName{
		NameType:   nametype.KRB_NT_SRV_INST,
		NameString: []string{"host", "server.test.com"},
	}
	realm := "TEST.COM"

	tgtReq := NewTGTReq(sname, realm)

	// Marshal
	b, err := tgtReq.Marshal()
	if err != nil {
		t.Fatalf("Error marshalling TGTReq: %v", err)
	}

	// Unmarshal
	var tgtReq2 TGTReq
	err = tgtReq2.Unmarshal(b)
	if err != nil {
		t.Fatalf("Error unmarshalling TGTReq: %v", err)
	}

	assert.Equal(t, tgtReq.PVNO, tgtReq2.PVNO, "PVNO mismatch")
	assert.Equal(t, tgtReq.MsgType, tgtReq2.MsgType, "MsgType mismatch")
	assert.Equal(t, tgtReq.ServerName.NameType, tgtReq2.ServerName.NameType, "ServerName NameType mismatch")
	assert.Equal(t, tgtReq.ServerName.NameString, tgtReq2.ServerName.NameString, "ServerName NameString mismatch")
	assert.Equal(t, tgtReq.Realm, tgtReq2.Realm, "Realm mismatch")
}

func TestTGTReq_MarshalUnmarshalWithEmptyOptionals(t *testing.T) {
	t.Parallel()
	// Create TGTReq with empty optional fields
	tgtReq := TGTReq{
		PVNO:    iana.PVNO,
		MsgType: msgtype.KRB_TGT_REQ,
	}

	// Marshal
	b, err := tgtReq.Marshal()
	if err != nil {
		t.Fatalf("Error marshalling TGTReq with empty optionals: %v", err)
	}

	// Unmarshal
	var tgtReq2 TGTReq
	err = tgtReq2.Unmarshal(b)
	if err != nil {
		t.Fatalf("Error unmarshalling TGTReq with empty optionals: %v", err)
	}

	assert.Equal(t, tgtReq.PVNO, tgtReq2.PVNO, "PVNO mismatch")
	assert.Equal(t, tgtReq.MsgType, tgtReq2.MsgType, "MsgType mismatch")
}

func TestTGTReq_UnmarshalInvalidMsgType(t *testing.T) {
	t.Parallel()
	// Create TGTReq with wrong message type
	tgtReq := TGTReq{
		PVNO:    iana.PVNO,
		MsgType: msgtype.KRB_AP_REQ, // Wrong type
		ServerName: types.PrincipalName{
			NameType:   nametype.KRB_NT_SRV_INST,
			NameString: []string{"HTTP", "service.example.com"},
		},
		Realm: "EXAMPLE.COM",
	}

	// Marshal
	b, err := tgtReq.Marshal()
	if err != nil {
		t.Fatalf("Error marshalling TGTReq: %v", err)
	}

	// Attempt to unmarshal - should fail due to wrong message type
	var tgtReq2 TGTReq
	err = tgtReq2.Unmarshal(b)
	assert.Error(t, err, "Unmarshal should fail with wrong message type")
	assert.Contains(t, err.Error(), "does not indicate a KRB_TGT_REQ", "Error message should indicate wrong message type")
}
