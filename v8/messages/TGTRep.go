package messages

import (
	"github.com/jcmturner/gofork/encoding/asn1"
	"github.com/jcmturner/gokrb5/v8/iana"
	"github.com/jcmturner/gokrb5/v8/iana/msgtype"
	"github.com/jcmturner/gokrb5/v8/krberror"
	"github.com/jcmturner/gokrb5/v8/types"
)

type marshalTGTRep struct {
	PVNO    int `asn1:"explicit,tag:0"`
	MsgType int `asn1:"explicit,tag:1"`
	// Ticket needs to be a raw value as it is wrapped in an APPLICATION tag
	Ticket     asn1.RawValue       `asn1:"explicit,tag:2"`
	ServerName types.PrincipalName `asn1:"optional,explicit,tag:4"`
}

// TGTRep implements KRB_TGT_REP for user-to-user authentication as defined in
// https://datatracker.ietf.org/doc/html/draft-swift-win2k-krb-user2user-03
type TGTRep struct {
	PVNO       int                 `asn1:"explicit,tag:0"`
	MsgType    int                 `asn1:"explicit,tag:1"`
	Ticket     Ticket              `asn1:"explicit,tag:2"`
	ServerName types.PrincipalName `asn1:"optional,explicit,tag:4"`
}

// NewTGTRep generates a new KRB_TGT_REP struct.
func NewTGTRep(ticket Ticket, sname types.PrincipalName) TGTRep {
	return TGTRep{
		PVNO:       iana.PVNO,
		MsgType:    msgtype.KRB_TGT_REP,
		Ticket:     ticket,
		ServerName: sname,
	}
}

// Unmarshal bytes b into the TGTRep struct.
func (t *TGTRep) Unmarshal(b []byte) error {
	var m marshalTGTRep
	_, err := asn1.Unmarshal(b, &m)
	if err != nil {
		return krberror.Errorf(err, krberror.EncodingError, "TGT_REP unmarshal error")
	}
	expectedMsgType := msgtype.KRB_TGT_REP
	if m.MsgType != expectedMsgType {
		return krberror.NewErrorf(krberror.KRBMsgError, "message ID does not indicate a KRB_TGT_REP. Expected: %v; Actual: %v", expectedMsgType, m.MsgType)
	}
	t.PVNO = m.PVNO
	t.MsgType = m.MsgType
	t.ServerName = m.ServerName
	t.Ticket, err = unmarshalTicket(m.Ticket.Bytes)
	if err != nil {
		return krberror.Errorf(err, krberror.EncodingError, "unmarshaling error of Ticket within TGT_REP")
	}
	return nil
}

// Marshal a TGTRep into bytes.
func (t *TGTRep) Marshal() ([]byte, error) {
	m := marshalTGTRep{
		PVNO:       t.PVNO,
		MsgType:    t.MsgType,
		ServerName: t.ServerName,
	}
	var b []byte
	b, err := t.Ticket.Marshal()
	if err != nil {
		return b, err
	}
	m.Ticket = asn1.RawValue{
		Class:      asn1.ClassContextSpecific,
		IsCompound: true,
		Tag:        2,
		Bytes:      b,
	}
	mk, err := asn1.Marshal(m)
	if err != nil {
		return mk, krberror.Errorf(err, krberror.EncodingError, "marshaling error of TGT_REP")
	}
	// TGT_REP uses message type 17, which doesn't have a standard ASN.1 application tag
	// It's sent as a raw sequence within the GSSAPI token
	return mk, nil
}
