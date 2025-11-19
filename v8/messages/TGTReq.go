package messages

import (
	"github.com/jcmturner/gofork/encoding/asn1"
	"github.com/jcmturner/gokrb5/v8/iana"
	"github.com/jcmturner/gokrb5/v8/iana/msgtype"
	"github.com/jcmturner/gokrb5/v8/krberror"
	"github.com/jcmturner/gokrb5/v8/types"
)

// TGTReq implements KRB_TGT_REQ for user-to-user authentication as defined in
// https://datatracker.ietf.org/doc/html/draft-swift-win2k-krb-user2user-03
type TGTReq struct {
	PVNO       int                 `asn1:"explicit,tag:0"`
	MsgType    int                 `asn1:"explicit,tag:1"`
	ServerName types.PrincipalName `asn1:"optional,explicit,tag:2"`
	Realm      string              `asn1:"generalstring,optional,explicit,tag:3"`
}

// NewTGTReq generates a new KRB_TGT_REQ struct.
func NewTGTReq(sname types.PrincipalName, realm string) TGTReq {
	return TGTReq{
		PVNO:       iana.PVNO,
		MsgType:    msgtype.KRB_TGT_REQ,
		ServerName: sname,
		Realm:      realm,
	}
}

// Unmarshal bytes b into the TGTReq struct.
func (t *TGTReq) Unmarshal(b []byte) error {
	_, err := asn1.Unmarshal(b, t)
	if err != nil {
		return krberror.Errorf(err, krberror.EncodingError, "TGT_REQ unmarshal error")
	}
	expectedMsgType := msgtype.KRB_TGT_REQ
	if t.MsgType != expectedMsgType {
		return krberror.NewErrorf(krberror.KRBMsgError, "message ID does not indicate a KRB_TGT_REQ. Expected: %v; Actual: %v", expectedMsgType, t.MsgType)
	}
	return nil
}

// Marshal a TGTReq into bytes.
func (t *TGTReq) Marshal() ([]byte, error) {
	b, err := asn1.Marshal(*t)
	if err != nil {
		return b, krberror.Errorf(err, krberror.EncodingError, "error marshaling TGT_REQ")
	}
	// TGT_REQ uses message type 16, which doesn't have a standard ASN.1 application tag
	// It's sent as a raw sequence within the GSSAPI token
	return b, nil
}
