package service

import (
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"github.com/jcmturner/gofork/encoding/asn1"
	"github.com/jcmturner/gokrb5/v8/asn1tools"
	"github.com/jcmturner/gokrb5/v8/client"
	"github.com/jcmturner/gokrb5/v8/config"
	"github.com/jcmturner/gokrb5/v8/credentials"
	"github.com/jcmturner/gokrb5/v8/crypto"
	"github.com/jcmturner/gokrb5/v8/iana"
	"github.com/jcmturner/gokrb5/v8/iana/asnAppTag"
	"github.com/jcmturner/gokrb5/v8/iana/errorcode"
	"github.com/jcmturner/gokrb5/v8/iana/flags"
	"github.com/jcmturner/gokrb5/v8/iana/keyusage"
	"github.com/jcmturner/gokrb5/v8/iana/nametype"
	"github.com/jcmturner/gokrb5/v8/keytab"
	"github.com/jcmturner/gokrb5/v8/messages"
	"github.com/jcmturner/gokrb5/v8/test/testdata"
	"github.com/jcmturner/gokrb5/v8/types"
	"github.com/stretchr/testify/assert"
)

func TestVerifyAPREQ(t *testing.T) {
	t.Parallel()
	cl := getClient()
	sname := types.PrincipalName{
		NameType:   nametype.KRB_NT_PRINCIPAL,
		NameString: []string{"HTTP", "host.test.gokrb5"},
	}
	b, _ := hex.DecodeString(testdata.HTTP_KEYTAB)
	kt := keytab.New()
	kt.Unmarshal(b)
	st := time.Now().UTC()
	tkt, sessionKey, err := messages.NewTicket(cl.Credentials.CName(), cl.Credentials.Domain(),
		sname, "TEST.GOKRB5",
		types.NewKrbFlags(),
		kt,
		18,
		1,
		st,
		st,
		st.Add(time.Duration(24)*time.Hour),
		st.Add(time.Duration(48)*time.Hour),
	)
	if err != nil {
		t.Fatalf("Error getting test ticket: %v", err)
	}
	APReq, err := messages.NewAPReq(
		tkt,
		sessionKey,
		newTestAuthenticator(*cl.Credentials),
	)
	if err != nil {
		t.Fatalf("Error getting test AP_REQ: %v", err)
	}

	h, _ := types.GetHostAddress("127.0.0.1:1234")
	s := NewSettings(kt, ClientAddress(h))
	ok, _, err := VerifyAPREQ(&APReq, s)
	if !ok || err != nil {
		t.Fatalf("Validation of AP_REQ failed when it should not have: %v", err)
	}
}

func TestVerifyAPREQWithPrincipalOverride(t *testing.T) {
	t.Parallel()
	cl := getClient()
	sname := types.PrincipalName{
		NameType:   nametype.KRB_NT_PRINCIPAL,
		NameString: []string{"HTTP", "host.test.gokrb5"},
	}
	b, _ := hex.DecodeString(testdata.HTTP_KEYTAB)
	kt := keytab.New()
	kt.Unmarshal(b)
	st := time.Now().UTC()
	tkt, sessionKey, err := messages.NewTicket(cl.Credentials.CName(), cl.Credentials.Domain(),
		sname, "TEST.GOKRB5",
		types.NewKrbFlags(),
		kt,
		18,
		1,
		st,
		st,
		st.Add(time.Duration(24)*time.Hour),
		st.Add(time.Duration(48)*time.Hour),
	)
	if err != nil {
		t.Fatalf("Error getting test ticket: %v", err)
	}
	apReq, err := messages.NewAPReq(
		tkt,
		sessionKey,
		newTestAuthenticator(*cl.Credentials),
	)
	if err != nil {
		t.Fatalf("Error getting test AP_REQ: %v", err)
	}

	h, _ := types.GetHostAddress("127.0.0.1:1234")
	s := NewSettings(kt, ClientAddress(h), KeytabPrincipal("foo"))
	ok, _, err := VerifyAPREQ(&apReq, s)
	if ok || err == nil {
		t.Fatalf("Validation of AP_REQ should have failed")
	}
	if !strings.Contains(err.Error(), "Looking for \"foo\" realm") {
		t.Fatalf("Looking for wrong entity: %s", err.Error())
	}
}

func TestVerifyAPREQ_KRB_AP_ERR_BADMATCH(t *testing.T) {
	t.Parallel()
	cl := getClient()
	sname := types.PrincipalName{
		NameType:   nametype.KRB_NT_PRINCIPAL,
		NameString: []string{"HTTP", "host.test.gokrb5"},
	}
	b, _ := hex.DecodeString(testdata.HTTP_KEYTAB)
	kt := keytab.New()
	kt.Unmarshal(b)
	st := time.Now().UTC()
	tkt, sessionKey, err := messages.NewTicket(cl.Credentials.CName(), cl.Credentials.Domain(),
		sname, "TEST.GOKRB5",
		types.NewKrbFlags(),
		kt,
		18,
		1,
		st,
		st,
		st.Add(time.Duration(24)*time.Hour),
		st.Add(time.Duration(48)*time.Hour),
	)
	if err != nil {
		t.Fatalf("Error getting test ticket: %v", err)
	}
	a := newTestAuthenticator(*cl.Credentials)
	a.CName = types.PrincipalName{
		NameType:   nametype.KRB_NT_PRINCIPAL,
		NameString: []string{"BADMATCH"},
	}
	APReq, err := messages.NewAPReq(
		tkt,
		sessionKey,
		a,
	)
	if err != nil {
		t.Fatalf("Error getting test AP_REQ: %v", err)
	}
	h, _ := types.GetHostAddress("127.0.0.1:1234")
	s := NewSettings(kt, ClientAddress(h))
	ok, _, err := VerifyAPREQ(&APReq, s)
	if ok || err == nil {
		t.Fatal("Validation of AP_REQ passed when it should not have")
	}
	if _, ok := err.(messages.KRBError); ok {
		assert.Equal(t, errorcode.KRB_AP_ERR_BADMATCH, err.(messages.KRBError).ErrorCode, "Error code not as expected")
	} else {
		t.Fatalf("Error is not a KRBError: %v", err)
	}
}

func TestVerifyAPREQ_LargeClockSkew(t *testing.T) {
	t.Parallel()
	cl := getClient()
	sname := types.PrincipalName{
		NameType:   nametype.KRB_NT_PRINCIPAL,
		NameString: []string{"HTTP", "host.test.gokrb5"},
	}
	b, _ := hex.DecodeString(testdata.HTTP_KEYTAB)
	kt := keytab.New()
	kt.Unmarshal(b)
	st := time.Now().UTC()
	tkt, sessionKey, err := messages.NewTicket(cl.Credentials.CName(), cl.Credentials.Domain(),
		sname, "TEST.GOKRB5",
		types.NewKrbFlags(),
		kt,
		18,
		1,
		st,
		st,
		st.Add(time.Duration(24)*time.Hour),
		st.Add(time.Duration(48)*time.Hour),
	)
	if err != nil {
		t.Fatalf("Error getting test ticket: %v", err)
	}
	a := newTestAuthenticator(*cl.Credentials)
	a.CTime = a.CTime.Add(time.Duration(-10) * time.Minute)
	APReq, err := messages.NewAPReq(
		tkt,
		sessionKey,
		a,
	)
	if err != nil {
		t.Fatalf("Error getting test AP_REQ: %v", err)
	}

	h, _ := types.GetHostAddress("127.0.0.1:1234")
	s := NewSettings(kt, ClientAddress(h))
	ok, _, err := VerifyAPREQ(&APReq, s)
	if ok || err == nil {
		t.Fatal("Validation of AP_REQ passed when it should not have")
	}
	if _, ok := err.(messages.KRBError); ok {
		assert.Equal(t, errorcode.KRB_AP_ERR_SKEW, err.(messages.KRBError).ErrorCode, "Error code not as expected")
	} else {
		t.Fatalf("Error is not a KRBError: %v", err)
	}
}

func TestVerifyAPREQ_Replay(t *testing.T) {
	t.Parallel()
	cl := getClient()
	sname := types.PrincipalName{
		NameType:   nametype.KRB_NT_PRINCIPAL,
		NameString: []string{"HTTP", "host.test.gokrb5"},
	}
	b, _ := hex.DecodeString(testdata.HTTP_KEYTAB)
	kt := keytab.New()
	kt.Unmarshal(b)
	st := time.Now().UTC()
	tkt, sessionKey, err := messages.NewTicket(cl.Credentials.CName(), cl.Credentials.Domain(),
		sname, "TEST.GOKRB5",
		types.NewKrbFlags(),
		kt,
		18,
		1,
		st,
		st,
		st.Add(time.Duration(24)*time.Hour),
		st.Add(time.Duration(48)*time.Hour),
	)
	if err != nil {
		t.Fatalf("Error getting test ticket: %v", err)
	}
	APReq, err := messages.NewAPReq(
		tkt,
		sessionKey,
		newTestAuthenticator(*cl.Credentials),
	)
	if err != nil {
		t.Fatalf("Error getting test AP_REQ: %v", err)
	}

	h, _ := types.GetHostAddress("127.0.0.1:1234")
	s := NewSettings(kt, ClientAddress(h))
	ok, _, err := VerifyAPREQ(&APReq, s)
	if !ok || err != nil {
		t.Fatalf("Validation of AP_REQ failed when it should not have: %v", err)
	}
	// Replay
	ok, _, err = VerifyAPREQ(&APReq, s)
	if ok || err == nil {
		t.Fatal("Validation of AP_REQ passed when it should not have")
	}
	assert.IsType(t, messages.KRBError{}, err, "Error is not a KRBError")
	assert.Equal(t, errorcode.KRB_AP_ERR_REPEAT, err.(messages.KRBError).ErrorCode, "Error code not as expected")
}

func TestVerifyAPREQ_FutureTicket(t *testing.T) {
	t.Parallel()
	cl := getClient()
	sname := types.PrincipalName{
		NameType:   nametype.KRB_NT_PRINCIPAL,
		NameString: []string{"HTTP", "host.test.gokrb5"},
	}
	b, _ := hex.DecodeString(testdata.HTTP_KEYTAB)
	kt := keytab.New()
	kt.Unmarshal(b)
	st := time.Now().UTC()
	tkt, sessionKey, err := messages.NewTicket(cl.Credentials.CName(), cl.Credentials.Domain(),
		sname, "TEST.GOKRB5",
		types.NewKrbFlags(),
		kt,
		18,
		1,
		st,
		st.Add(time.Duration(60)*time.Minute),
		st.Add(time.Duration(24)*time.Hour),
		st.Add(time.Duration(48)*time.Hour),
	)
	if err != nil {
		t.Fatalf("Error getting test ticket: %v", err)
	}
	a := newTestAuthenticator(*cl.Credentials)
	APReq, err := messages.NewAPReq(
		tkt,
		sessionKey,
		a,
	)
	if err != nil {
		t.Fatalf("Error getting test AP_REQ: %v", err)
	}

	h, _ := types.GetHostAddress("127.0.0.1:1234")
	s := NewSettings(kt, ClientAddress(h))
	ok, _, err := VerifyAPREQ(&APReq, s)
	if ok || err == nil {
		t.Fatal("Validation of AP_REQ passed when it should not have")
	}
	if _, ok := err.(messages.KRBError); ok {
		assert.Equal(t, errorcode.KRB_AP_ERR_TKT_NYV, err.(messages.KRBError).ErrorCode, "Error code not as expected")
	} else {
		t.Fatalf("Error is not a KRBError: %v", err)
	}
}

func TestVerifyAPREQ_InvalidTicket(t *testing.T) {
	t.Parallel()
	cl := getClient()
	sname := types.PrincipalName{
		NameType:   nametype.KRB_NT_PRINCIPAL,
		NameString: []string{"HTTP", "host.test.gokrb5"},
	}
	b, _ := hex.DecodeString(testdata.HTTP_KEYTAB)
	kt := keytab.New()
	kt.Unmarshal(b)
	st := time.Now().UTC()
	f := types.NewKrbFlags()
	types.SetFlag(&f, flags.Invalid)
	tkt, sessionKey, err := messages.NewTicket(cl.Credentials.CName(), cl.Credentials.Domain(),
		sname, "TEST.GOKRB5",
		f,
		kt,
		18,
		1,
		st,
		st,
		st.Add(time.Duration(24)*time.Hour),
		st.Add(time.Duration(48)*time.Hour),
	)
	if err != nil {
		t.Fatalf("Error getting test ticket: %v", err)
	}
	APReq, err := messages.NewAPReq(
		tkt,
		sessionKey,
		newTestAuthenticator(*cl.Credentials),
	)
	if err != nil {
		t.Fatalf("Error getting test AP_REQ: %v", err)
	}

	h, _ := types.GetHostAddress("127.0.0.1:1234")
	s := NewSettings(kt, ClientAddress(h))
	ok, _, err := VerifyAPREQ(&APReq, s)
	if ok || err == nil {
		t.Fatal("Validation of AP_REQ passed when it should not have")
	}
	if _, ok := err.(messages.KRBError); ok {
		assert.Equal(t, errorcode.KRB_AP_ERR_TKT_NYV, err.(messages.KRBError).ErrorCode, "Error code not as expected")
	} else {
		t.Fatalf("Error is not a KRBError: %v", err)
	}
}

func TestVerifyAPREQ_ExpiredTicket(t *testing.T) {
	t.Parallel()
	cl := getClient()
	sname := types.PrincipalName{
		NameType:   nametype.KRB_NT_PRINCIPAL,
		NameString: []string{"HTTP", "host.test.gokrb5"},
	}
	b, _ := hex.DecodeString(testdata.HTTP_KEYTAB)
	kt := keytab.New()
	kt.Unmarshal(b)
	st := time.Now().UTC()
	tkt, sessionKey, err := messages.NewTicket(cl.Credentials.CName(), cl.Credentials.Domain(),
		sname, "TEST.GOKRB5",
		types.NewKrbFlags(),
		kt,
		18,
		1,
		st,
		st,
		st.Add(time.Duration(-30)*time.Minute),
		st.Add(time.Duration(48)*time.Hour),
	)
	if err != nil {
		t.Fatalf("Error getting test ticket: %v", err)
	}
	a := newTestAuthenticator(*cl.Credentials)
	APReq, err := messages.NewAPReq(
		tkt,
		sessionKey,
		a,
	)
	if err != nil {
		t.Fatalf("Error getting test AP_REQ: %v", err)
	}

	h, _ := types.GetHostAddress("127.0.0.1:1234")
	s := NewSettings(kt, ClientAddress(h))
	ok, _, err := VerifyAPREQ(&APReq, s)
	if ok || err == nil {
		t.Fatal("Validation of AP_REQ passed when it should not have")
	}
	if _, ok := err.(messages.KRBError); ok {
		assert.Equal(t, errorcode.KRB_AP_ERR_TKT_EXPIRED, err.(messages.KRBError).ErrorCode, "Error code not as expected")
	} else {
		t.Fatalf("Error is not a KRBError: %v", err)
	}
}

func newTestAuthenticator(creds credentials.Credentials) types.Authenticator {
	auth, _ := types.NewAuthenticator(creds.Domain(), creds.CName())
	auth.GenerateSeqNumberAndSubKey(18, 32)
	//auth.Cksum = types.Checksum{
	//	CksumType: chksumtype.GSSAPI,
	//	Checksum:  newAuthenticatorChksum([]int{GSS_C_INTEG_FLAG, GSS_C_CONF_FLAG}),
	//}
	return auth
}

func getClient() *client.Client {
	b, _ := hex.DecodeString(testdata.KEYTAB_TESTUSER1_TEST_GOKRB5)
	kt := keytab.New()
	kt.Unmarshal(b)
	c, _ := config.NewFromString(testdata.KRB5_CONF)
	cl := client.NewWithKeytab("testuser1", "TEST.GOKRB5", kt, c)
	return cl
}

// newTicketWithSessionKey creates a ticket encrypted with the provided session key
// instead of using a keytab. This is used for testing User-to-User authentication.
func newTicketWithSessionKey(cname types.PrincipalName, crealm string, sname types.PrincipalName, srealm string, flags asn1.BitString, encryptionKey types.EncryptionKey, eTypeID int32, kvno int, authTime, startTime, endTime, renewTill time.Time) (messages.Ticket, types.EncryptionKey, error) {
	etype, err := crypto.GetEtype(eTypeID)
	if err != nil {
		return messages.Ticket{}, types.EncryptionKey{}, err
	}
	sessionKey, err := types.GenerateEncryptionKey(etype)
	if err != nil {
		return messages.Ticket{}, types.EncryptionKey{}, err
	}

	etp := messages.EncTicketPart{
		Flags:     flags,
		Key:       sessionKey,
		CRealm:    crealm,
		CName:     cname,
		Transited: messages.TransitedEncoding{},
		AuthTime:  authTime,
		StartTime: startTime,
		EndTime:   endTime,
		RenewTill: renewTill,
	}
	b, err := asn1.Marshal(etp)
	if err != nil {
		return messages.Ticket{}, types.EncryptionKey{}, err
	}
	b = asn1tools.AddASNAppTag(b, asnAppTag.EncTicketPart)
	ed, err := crypto.GetEncryptedData(b, encryptionKey, keyusage.KDC_REP_TICKET, kvno)
	if err != nil {
		return messages.Ticket{}, types.EncryptionKey{}, err
	}
	tkt := messages.Ticket{
		TktVNO:  iana.PVNO,
		Realm:   srealm,
		SName:   sname,
		EncPart: ed,
	}
	return tkt, sessionKey, nil
}

func TestVerifyUser2UserAPREQ(t *testing.T) {
	t.Parallel()
	cl := getClient()
	sname := types.PrincipalName{
		NameType:   nametype.KRB_NT_PRINCIPAL,
		NameString: []string{"HTTP", "host.test.gokrb5"},
	}
	st := time.Now().UTC()

	// Create a TGT session key for the service
	tgtSessionKey := types.EncryptionKey{
		KeyType:  18,
		KeyValue: []byte("test_tgt_session_key_12345678901"),
	}

	// Create a ticket encrypted with the TGT session key (for user-to-user authentication)
	tkt, sessionKey, err := newTicketWithSessionKey(cl.Credentials.CName(), cl.Credentials.Domain(),
		sname, "TEST.GOKRB5",
		types.NewKrbFlags(),
		tgtSessionKey,
		18,
		1,
		st,
		st,
		st.Add(time.Duration(24)*time.Hour),
		st.Add(time.Duration(48)*time.Hour),
	)
	if err != nil {
		t.Fatalf("Error getting test ticket: %v", err)
	}

	// Create AP_REQ with APOptionUseSessionKey flag
	APReq, err := messages.NewAPReq(
		tkt,
		sessionKey,
		newTestAuthenticator(*cl.Credentials),
	)
	if err != nil {
		t.Fatalf("Error getting test AP_REQ: %v", err)
	}
	// Set the APOptionUseSessionKey flag for user-to-user authentication
	types.SetFlag(&APReq.APOptions, flags.APOptionUseSessionKey)

	h, _ := types.GetHostAddress("127.0.0.1:1234")
	s := NewSettings(nil, ClientAddress(h), TGTSessionKey(tgtSessionKey))
	ok, _, err := VerifyUser2UserAPREQ(&APReq, s)
	if !ok || err != nil {
		t.Fatalf("Validation of User2User AP_REQ failed when it should not have: %v", err)
	}
}

func TestVerifyUser2UserAPREQ_MissingAPOptionUseSessionKey(t *testing.T) {
	t.Parallel()
	cl := getClient()
	sname := types.PrincipalName{
		NameType:   nametype.KRB_NT_PRINCIPAL,
		NameString: []string{"HTTP", "host.test.gokrb5"},
	}
	st := time.Now().UTC()

	tgtSessionKey := types.EncryptionKey{
		KeyType:  18,
		KeyValue: []byte("test_tgt_session_key_12345678901"),
	}

	tkt, sessionKey, err := newTicketWithSessionKey(cl.Credentials.CName(), cl.Credentials.Domain(),
		sname, "TEST.GOKRB5",
		types.NewKrbFlags(),
		tgtSessionKey,
		18,
		1,
		st,
		st,
		st.Add(time.Duration(24)*time.Hour),
		st.Add(time.Duration(48)*time.Hour),
	)
	if err != nil {
		t.Fatalf("Error getting test ticket: %v", err)
	}

	// Create AP_REQ WITHOUT APOptionUseSessionKey flag
	APReq, err := messages.NewAPReq(
		tkt,
		sessionKey,
		newTestAuthenticator(*cl.Credentials),
	)
	if err != nil {
		t.Fatalf("Error getting test AP_REQ: %v", err)
	}
	// Don't set the APOptionUseSessionKey flag

	h, _ := types.GetHostAddress("127.0.0.1:1234")
	s := NewSettings(nil, ClientAddress(h), TGTSessionKey(tgtSessionKey))
	ok, _, err := VerifyUser2UserAPREQ(&APReq, s)
	if ok || err == nil {
		t.Fatal("Validation of User2User AP_REQ passed when it should not have (missing APOptionUseSessionKey)")
	}
	if _, ok := err.(messages.KRBError); ok {
		assert.Equal(t, errorcode.KRB_AP_ERR_BAD_INTEGRITY, err.(messages.KRBError).ErrorCode, "Error code not as expected")
	} else {
		t.Fatalf("Error is not a KRBError: %v", err)
	}
}

func TestVerifyUser2UserAPREQ_MissingTGTSessionKey(t *testing.T) {
	t.Parallel()
	cl := getClient()
	sname := types.PrincipalName{
		NameType:   nametype.KRB_NT_PRINCIPAL,
		NameString: []string{"HTTP", "host.test.gokrb5"},
	}
	st := time.Now().UTC()

	tgtSessionKey := types.EncryptionKey{
		KeyType:  18,
		KeyValue: []byte("test_tgt_session_key_12345678901"),
	}

	tkt, sessionKey, err := newTicketWithSessionKey(cl.Credentials.CName(), cl.Credentials.Domain(),
		sname, "TEST.GOKRB5",
		types.NewKrbFlags(),
		tgtSessionKey,
		18,
		1,
		st,
		st,
		st.Add(time.Duration(24)*time.Hour),
		st.Add(time.Duration(48)*time.Hour),
	)
	if err != nil {
		t.Fatalf("Error getting test ticket: %v", err)
	}

	APReq, err := messages.NewAPReq(
		tkt,
		sessionKey,
		newTestAuthenticator(*cl.Credentials),
	)
	if err != nil {
		t.Fatalf("Error getting test AP_REQ: %v", err)
	}
	types.SetFlag(&APReq.APOptions, flags.APOptionUseSessionKey)

	h, _ := types.GetHostAddress("127.0.0.1:1234")
	// Create settings WITHOUT TGT session key
	s := NewSettings(nil, ClientAddress(h))
	ok, _, err := VerifyUser2UserAPREQ(&APReq, s)
	if ok || err == nil {
		t.Fatal("Validation of User2User AP_REQ passed when it should not have (missing TGT session key)")
	}
	if _, ok := err.(messages.KRBError); ok {
		assert.Equal(t, errorcode.KRB_AP_ERR_NOKEY, err.(messages.KRBError).ErrorCode, "Error code not as expected")
	} else {
		t.Fatalf("Error is not a KRBError: %v", err)
	}
}

func TestVerifyUser2UserAPREQ_Replay(t *testing.T) {
	t.Parallel()
	cl := getClient()
	sname := types.PrincipalName{
		NameType:   nametype.KRB_NT_PRINCIPAL,
		NameString: []string{"HTTP", "host.test.gokrb5"},
	}
	st := time.Now().UTC()

	tgtSessionKey := types.EncryptionKey{
		KeyType:  18,
		KeyValue: []byte("test_tgt_session_key_12345678901"),
	}

	tkt, sessionKey, err := newTicketWithSessionKey(cl.Credentials.CName(), cl.Credentials.Domain(),
		sname, "TEST.GOKRB5",
		types.NewKrbFlags(),
		tgtSessionKey,
		18,
		1,
		st,
		st,
		st.Add(time.Duration(24)*time.Hour),
		st.Add(time.Duration(48)*time.Hour),
	)
	if err != nil {
		t.Fatalf("Error getting test ticket: %v", err)
	}

	APReq, err := messages.NewAPReq(
		tkt,
		sessionKey,
		newTestAuthenticator(*cl.Credentials),
	)
	if err != nil {
		t.Fatalf("Error getting test AP_REQ: %v", err)
	}
	types.SetFlag(&APReq.APOptions, flags.APOptionUseSessionKey)

	h, _ := types.GetHostAddress("127.0.0.1:1234")
	s := NewSettings(nil, ClientAddress(h), TGTSessionKey(tgtSessionKey))

	// First verification should succeed
	ok, _, err := VerifyUser2UserAPREQ(&APReq, s)
	if !ok || err != nil {
		t.Fatalf("First validation of User2User AP_REQ failed when it should not have: %v", err)
	}

	// Replay should fail
	ok, _, err = VerifyUser2UserAPREQ(&APReq, s)
	if ok || err == nil {
		t.Fatal("Validation of replayed User2User AP_REQ passed when it should not have")
	}
	assert.IsType(t, messages.KRBError{}, err, "Error is not a KRBError")
	assert.Equal(t, errorcode.KRB_AP_ERR_REPEAT, err.(messages.KRBError).ErrorCode, "Error code not as expected")
}

func TestVerifyUser2UserAPREQ_LargeClockSkew(t *testing.T) {
	t.Parallel()
	cl := getClient()
	sname := types.PrincipalName{
		NameType:   nametype.KRB_NT_PRINCIPAL,
		NameString: []string{"HTTP", "host.test.gokrb5"},
	}
	st := time.Now().UTC()

	tgtSessionKey := types.EncryptionKey{
		KeyType:  18,
		KeyValue: []byte("test_tgt_session_key_12345678901"),
	}

	tkt, sessionKey, err := newTicketWithSessionKey(cl.Credentials.CName(), cl.Credentials.Domain(),
		sname, "TEST.GOKRB5",
		types.NewKrbFlags(),
		tgtSessionKey,
		18,
		1,
		st,
		st,
		st.Add(time.Duration(24)*time.Hour),
		st.Add(time.Duration(48)*time.Hour),
	)
	if err != nil {
		t.Fatalf("Error getting test ticket: %v", err)
	}

	// Create authenticator with time in the past (large clock skew)
	a := newTestAuthenticator(*cl.Credentials)
	a.CTime = a.CTime.Add(time.Duration(-10) * time.Minute)
	APReq, err := messages.NewAPReq(
		tkt,
		sessionKey,
		a,
	)
	if err != nil {
		t.Fatalf("Error getting test AP_REQ: %v", err)
	}
	types.SetFlag(&APReq.APOptions, flags.APOptionUseSessionKey)

	h, _ := types.GetHostAddress("127.0.0.1:1234")
	s := NewSettings(nil, ClientAddress(h), TGTSessionKey(tgtSessionKey))
	ok, _, err := VerifyUser2UserAPREQ(&APReq, s)
	if ok || err == nil {
		t.Fatal("Validation of User2User AP_REQ passed when it should not have (large clock skew)")
	}
	if _, ok := err.(messages.KRBError); ok {
		assert.Equal(t, errorcode.KRB_AP_ERR_SKEW, err.(messages.KRBError).ErrorCode, "Error code not as expected")
	} else {
		t.Fatalf("Error is not a KRBError: %v", err)
	}
}

func TestVerifyUser2UserAPREQ_KRB_AP_ERR_BADMATCH(t *testing.T) {
	t.Parallel()
	cl := getClient()
	sname := types.PrincipalName{
		NameType:   nametype.KRB_NT_PRINCIPAL,
		NameString: []string{"HTTP", "host.test.gokrb5"},
	}
	st := time.Now().UTC()

	tgtSessionKey := types.EncryptionKey{
		KeyType:  18,
		KeyValue: []byte("test_tgt_session_key_12345678901"),
	}

	tkt, sessionKey, err := newTicketWithSessionKey(cl.Credentials.CName(), cl.Credentials.Domain(),
		sname, "TEST.GOKRB5",
		types.NewKrbFlags(),
		tgtSessionKey,
		18,
		1,
		st,
		st,
		st.Add(time.Duration(24)*time.Hour),
		st.Add(time.Duration(48)*time.Hour),
	)
	if err != nil {
		t.Fatalf("Error getting test ticket: %v", err)
	}

	// Create authenticator with mismatched CName
	a := newTestAuthenticator(*cl.Credentials)
	a.CName = types.PrincipalName{
		NameType:   nametype.KRB_NT_PRINCIPAL,
		NameString: []string{"BADMATCH"},
	}
	APReq, err := messages.NewAPReq(
		tkt,
		sessionKey,
		a,
	)
	if err != nil {
		t.Fatalf("Error getting test AP_REQ: %v", err)
	}
	types.SetFlag(&APReq.APOptions, flags.APOptionUseSessionKey)

	h, _ := types.GetHostAddress("127.0.0.1:1234")
	s := NewSettings(nil, ClientAddress(h), TGTSessionKey(tgtSessionKey))
	ok, _, err := VerifyUser2UserAPREQ(&APReq, s)
	if ok || err == nil {
		t.Fatal("Validation of User2User AP_REQ passed when it should not have (CName mismatch)")
	}
	if _, ok := err.(messages.KRBError); ok {
		assert.Equal(t, errorcode.KRB_AP_ERR_BADMATCH, err.(messages.KRBError).ErrorCode, "Error code not as expected")
	} else {
		t.Fatalf("Error is not a KRBError: %v", err)
	}
}
