package messages

import (
	"testing"

	"github.com/jcmturner/gokrb5/v8/iana"
	"github.com/jcmturner/gokrb5/v8/iana/msgtype"
	"github.com/jcmturner/gokrb5/v8/iana/nametype"
	"github.com/jcmturner/gokrb5/v8/test/testdata"
	"github.com/jcmturner/gokrb5/v8/types"
	"github.com/stretchr/testify/assert"
)

func TestTGTRep_New(t *testing.T) {
	t.Parallel()
	ticket := Ticket{
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

	tgtRep := NewTGTRep(ticket, sname)

	assert.Equal(t, iana.PVNO, tgtRep.PVNO, "PVNO not as expected")
	assert.Equal(t, msgtype.KRB_TGT_REP, tgtRep.MsgType, "MsgType not as expected")
	assert.Equal(t, 5, tgtRep.Ticket.TktVNO, "Ticket TktVNO not as expected")
	assert.Equal(t, sname.NameString, tgtRep.ServerName.NameString, "ServerName not as expected")
}

func TestTGTRep_MarshalUnmarshal(t *testing.T) {
	t.Parallel()
	ticket := Ticket{
		TktVNO: 5,
		Realm:  "TEST.EXAMPLE.COM",
		SName: types.PrincipalName{
			NameType:   nametype.KRB_NT_SRV_INST,
			NameString: []string{"krbtgt", "TEST.EXAMPLE.COM"},
		},
		EncPart: types.EncryptedData{
			EType:  18, // AES256-CTS-HMAC-SHA1-96
			KVNO:   1,
			Cipher: []byte{1, 2, 3, 4, 5},
		},
	}
	sname := types.PrincipalName{
		NameType:   nametype.KRB_NT_SRV_INST,
		NameString: []string{"krbtgt", "TEST.EXAMPLE.COM"},
	}

	tgtRep := NewTGTRep(ticket, sname)

	// Marshal
	b, err := tgtRep.Marshal()
	if err != nil {
		t.Fatalf("Error marshalling TGTRep: %v", err)
	}

	// Unmarshal
	var tgtRep2 TGTRep
	err = tgtRep2.Unmarshal(b)
	if err != nil {
		t.Fatalf("Error unmarshalling TGTRep: %v", err)
	}

	assert.Equal(t, tgtRep.PVNO, tgtRep2.PVNO, "PVNO mismatch")
	assert.Equal(t, tgtRep.MsgType, tgtRep2.MsgType, "MsgType mismatch")
	assert.Equal(t, tgtRep.Ticket.TktVNO, tgtRep2.Ticket.TktVNO, "Ticket TktVNO mismatch")
	assert.Equal(t, tgtRep.Ticket.Realm, tgtRep2.Ticket.Realm, "Ticket Realm mismatch")
	assert.Equal(t, tgtRep.Ticket.SName.NameString, tgtRep2.Ticket.SName.NameString, "Ticket SName mismatch")
	assert.Equal(t, tgtRep.ServerName.NameType, tgtRep2.ServerName.NameType, "ServerName NameType mismatch")
	assert.Equal(t, tgtRep.ServerName.NameString, tgtRep2.ServerName.NameString, "ServerName NameString mismatch")
}

func TestTGTRep_MarshalUnmarshalWithEmptyOptionalServerName(t *testing.T) {
	t.Parallel()
	ticket := Ticket{
		TktVNO: 5,
		Realm:  "TEST.COM",
		SName: types.PrincipalName{
			NameType:   nametype.KRB_NT_SRV_INST,
			NameString: []string{"krbtgt", "TEST.COM"},
		},
		EncPart: types.EncryptedData{
			EType:  18,
			KVNO:   1,
			Cipher: []byte{1, 2, 3, 4, 5},
		},
	}

	// Create TGTRep with empty optional ServerName field
	tgtRep := TGTRep{
		PVNO:    iana.PVNO,
		MsgType: msgtype.KRB_TGT_REP,
		Ticket:  ticket,
	}

	// Marshal
	b, err := tgtRep.Marshal()
	if err != nil {
		t.Fatalf("Error marshalling TGTRep with empty ServerName: %v", err)
	}

	// Unmarshal
	var tgtRep2 TGTRep
	err = tgtRep2.Unmarshal(b)
	if err != nil {
		t.Fatalf("Error unmarshalling TGTRep with empty ServerName: %v", err)
	}

	assert.Equal(t, tgtRep.PVNO, tgtRep2.PVNO, "PVNO mismatch")
	assert.Equal(t, tgtRep.MsgType, tgtRep2.MsgType, "MsgType mismatch")
	assert.Equal(t, tgtRep.Ticket.TktVNO, tgtRep2.Ticket.TktVNO, "Ticket TktVNO mismatch")
}

func TestTGTRep_UnmarshalInvalidMsgType(t *testing.T) {
	t.Parallel()
	ticket := Ticket{
		TktVNO: 5,
		Realm:  "TEST.COM",
		SName: types.PrincipalName{
			NameType:   nametype.KRB_NT_SRV_INST,
			NameString: []string{"krbtgt", "TEST.COM"},
		},
		EncPart: types.EncryptedData{
			EType:  18,
			KVNO:   1,
			Cipher: []byte{1, 2, 3, 4, 5},
		},
	}

	// Create TGTRep with wrong message type
	tgtRep := TGTRep{
		PVNO:    iana.PVNO,
		MsgType: msgtype.KRB_AP_REP, // Wrong type
		Ticket:  ticket,
		ServerName: types.PrincipalName{
			NameType:   nametype.KRB_NT_SRV_INST,
			NameString: []string{"krbtgt", "TEST.COM"},
		},
	}

	// Marshal
	b, err := tgtRep.Marshal()
	if err != nil {
		t.Fatalf("Error marshalling TGTRep: %v", err)
	}

	// Attempt to unmarshal - should fail due to wrong message type
	var tgtRep2 TGTRep
	err = tgtRep2.Unmarshal(b)
	assert.Error(t, err, "Unmarshal should fail with wrong message type")
	assert.Contains(t, err.Error(), "does not indicate a KRB_TGT_REP", "Error message should indicate wrong message type")
}
