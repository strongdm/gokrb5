package spnego

import (
	"encoding/hex"
	"math"
	"testing"

	"github.com/jcmturner/gofork/encoding/asn1"
	"github.com/jcmturner/gokrb5/v8/client"
	"github.com/jcmturner/gokrb5/v8/credentials"
	"github.com/jcmturner/gokrb5/v8/gssapi"
	"github.com/jcmturner/gokrb5/v8/iana/flags"
	"github.com/jcmturner/gokrb5/v8/iana/msgtype"
	"github.com/jcmturner/gokrb5/v8/iana/nametype"
	"github.com/jcmturner/gokrb5/v8/messages"
	"github.com/jcmturner/gokrb5/v8/test/testdata"
	"github.com/jcmturner/gokrb5/v8/types"
	"github.com/stretchr/testify/assert"
)

const (
	KRB5TokenHex = "6082026306092a864886f71201020201006e8202523082024ea003020105a10302010ea20703050000000000a382015d6182015930820155a003020105a10d1b0b544553542e474f4b524235a2233021a003020101a11a30181b04485454501b10686f73742e746573742e676f6b726235a382011830820114a003020112a103020103a28201060482010230621d868c97f30bf401e03bbffcd724bd9d067dce2afc31f71a356449b070cdafcc1ff372d0eb1e7a708b50c0152f3996c45b1ea312a803907fb97192d39f20cdcaea29876190f51de6e2b4a4df0460122ed97f363434e1e120b0e76c172b4424a536987152ac0b73013ab88af4b13a3fcdc63f739039dd46d839709cf5b51bb0ce6cb3af05fab3844caac280929955495235e9d0424f8a1fb9b4bd4f6bba971f40b97e9da60b9dabfcf0b1feebfca02c9a19b327a0004aa8e19192726cf347561fa8ac74afad5d6a264e50cf495b93aac86c77b2bc2d184234f6c2767dbea431485a25687b9044a20b601e968efaefffa1fc5283ff32aa6a53cb6c5cdd2eddcb26a481d73081d4a003020112a103020103a281c70481c4a1b29e420324f7edf9efae39df7bcaaf196a3160cf07e72f52a4ef8a965721b2f3343719c50699046e4fcc18ca26c2bfc7e4a9eddfc9d9cfc57ff2f6bdbbd1fc40ac442195bc669b9a0dbba12563b3e4cac9f4022fc01b8aa2d1ab84815bb078399ff7f4d5f9815eef896a0c7e3c049e6fd9932b97096cdb5861425b9d81753d0743212ded1a0fb55a00bf71a46be5ce5e1c8a5cc327b914347d9efcb6cb31ca363b1850d95c7b6c4c3cc6301615ad907318a0c5379d343610fab17eca9c7dc0a5a60658"
	AuthChksum   = "100000000000000000000000000000000000000030000000"
)

func TestKRB5Token_Unmarshal(t *testing.T) {
	t.Parallel()
	b, err := hex.DecodeString(KRB5TokenHex)
	if err != nil {
		t.Fatalf("Error decoding KRB5Token hex: %v", err)
	}
	var mt KRB5Token
	err = mt.Unmarshal(b)
	if err != nil {
		t.Fatalf("Error unmarshalling KRB5Token: %v", err)
	}
	assert.Equal(t, gssapi.OIDKRB5.OID(), mt.OID, "KRB5Token OID not as expected.")
	assert.Equal(t, []byte{1, 0}, mt.tokID, "TokID not as expected")
	assert.Equal(t, msgtype.KRB_AP_REQ, mt.APReq.MsgType, "KRB5Token AP_REQ does not have the right message type.")
	assert.Equal(t, int32(0), mt.KRBError.ErrorCode, "KRBError in KRB5Token does not indicate no error.")
	assert.Equal(t, int32(18), mt.APReq.EncryptedAuthenticator.EType, "Authenticator within AP_REQ does not have the etype expected.")
}

func TestKRB5Token_newAuthenticatorChksum(t *testing.T) {
	t.Parallel()
	b, err := hex.DecodeString(AuthChksum)
	if err != nil {
		t.Fatalf("Error decoding KRB5Token hex: %v", err)
	}
	cb := newAuthenticatorChksum([]int{gssapi.ContextFlagInteg, gssapi.ContextFlagConf})
	assert.Equal(t, b, cb, "SPNEGO Authenticator checksum not as expected")
}

// Test with explicit subkey generation.
func TestKRB5Token_newAuthenticatorWithSubkeyGeneration(t *testing.T) {
	t.Parallel()
	creds := credentials.New("hftsai", testdata.TEST_REALM)
	creds.SetCName(types.PrincipalName{NameType: nametype.KRB_NT_PRINCIPAL, NameString: testdata.TEST_PRINCIPALNAME_NAMESTRING})
	var etypeID int32 = 18
	keyLen := 32 // etypeID 18 refers to AES256 -> 32 bytes key
	a, err := krb5TokenAuthenticator(creds, []int{gssapi.ContextFlagInteg, gssapi.ContextFlagConf})
	if err != nil {
		t.Fatalf("Error creating authenticator: %v", err)
	}
	a.GenerateSeqNumberAndSubKey(etypeID, keyLen)
	assert.Equal(t, int32(32771), a.Cksum.CksumType, "Checksum type in authenticator for SPNEGO mechtoken not as expected.")
	assert.Equal(t, etypeID, a.SubKey.KeyType, "Subkey not of the expected type.")
	assert.Equal(t, keyLen, len(a.SubKey.KeyValue), "Subkey value not of the right length")
	var nz bool
	for _, b := range a.SubKey.KeyValue {
		if b != byte(0) {
			nz = true
		}
	}
	assert.True(t, nz, "subkey not initialised")
	assert.Condition(t, assert.Comparison(func() bool {
		return a.SeqNumber > 0
	}), "Sequence number is not greater than zero")
	assert.Condition(t, assert.Comparison(func() bool {
		return a.SeqNumber <= math.MaxUint32
	}))
}

// Test without subkey generation.
func TestKRB5Token_newAuthenticator(t *testing.T) {
	t.Parallel()
	creds := credentials.New("hftsai", testdata.TEST_REALM)
	creds.SetCName(types.PrincipalName{NameType: nametype.KRB_NT_PRINCIPAL, NameString: testdata.TEST_PRINCIPALNAME_NAMESTRING})
	a, err := krb5TokenAuthenticator(creds, []int{gssapi.ContextFlagInteg, gssapi.ContextFlagConf})
	if err != nil {
		t.Fatalf("Error creating authenticator: %v", err)
	}
	assert.Equal(t, int32(32771), a.Cksum.CksumType, "Checksum type in authenticator for SPNEGO mechtoken not as expected.")
	assert.Equal(t, int32(0), a.SubKey.KeyType, "Subkey not of the expected type.")
	assert.Nil(t, a.SubKey.KeyValue, "Subkey should not be set.")

	assert.Condition(t, assert.Comparison(func() bool {
		return a.SeqNumber > 0
	}), "Sequence number is not greater than zero")
	assert.Condition(t, assert.Comparison(func() bool {
		return a.SeqNumber <= math.MaxUint32
	}))
}

func TestNewAPREQKRB5Token_and_Marshal(t *testing.T) {
	t.Parallel()
	creds := credentials.New("hftsai", testdata.TEST_REALM)
	creds.SetCName(types.PrincipalName{NameType: nametype.KRB_NT_PRINCIPAL, NameString: testdata.TEST_PRINCIPALNAME_NAMESTRING})
	cl := client.Client{
		Credentials: creds,
	}

	var tkt messages.Ticket
	b, err := hex.DecodeString(testdata.MarshaledKRB5ticket)
	if err != nil {
		t.Fatalf("Test vector read error: %v", err)
	}
	err = tkt.Unmarshal(b)
	if err != nil {
		t.Fatalf("Unmarshal error: %v", err)
	}

	key := types.EncryptionKey{
		KeyType:  18,
		KeyValue: make([]byte, 32),
	}

	mt, err := NewKRB5TokenAPREQ(&cl, tkt, key, []int{gssapi.ContextFlagInteg, gssapi.ContextFlagConf}, []int{})
	if err != nil {
		t.Fatalf("Error creating KRB5Token: %v", err)
	}
	mb, err := mt.Marshal()
	if err != nil {
		t.Fatalf("Error unmarshalling KRB5Token: %v", err)
	}
	err = mt.Unmarshal(mb)
	if err != nil {
		t.Fatalf("Error unmarshalling KRB5Token: %v", err)
	}
	assert.Equal(t, asn1.ObjectIdentifier{1, 2, 840, 113554, 1, 2, 2}, mt.OID, "KRB5Token OID not as expected.")
	assert.Equal(t, []byte{1, 0}, mt.tokID, "TokID not as expected")
	assert.Equal(t, msgtype.KRB_AP_REQ, mt.APReq.MsgType, "KRB5Token AP_REQ does not have the right message type.")
	assert.Equal(t, int32(0), mt.KRBError.ErrorCode, "KRBError in KRB5Token does not indicate no error.")
	assert.Equal(t, testdata.TEST_REALM, mt.APReq.Ticket.Realm, "Realm in ticket within the AP_REQ of the KRB5Token not as expected.")
	assert.Equal(t, testdata.TEST_PRINCIPALNAME_NAMESTRING, mt.APReq.Ticket.SName.NameString, "SName in ticket within the AP_REQ of the KRB5Token not as expected.")
	assert.Equal(t, int32(18), mt.APReq.EncryptedAuthenticator.EType, "Authenticator within AP_REQ does not have the etype expected.")
}

func TestNewKRB5TokenUser2UserAPREQ(t *testing.T) {
	t.Parallel()
	creds := credentials.New("hftsai", testdata.TEST_REALM)
	creds.SetCName(types.PrincipalName{NameType: nametype.KRB_NT_PRINCIPAL, NameString: testdata.TEST_PRINCIPALNAME_NAMESTRING})
	cl := client.Client{
		Credentials: creds,
	}

	var tkt messages.Ticket
	b, err := hex.DecodeString(testdata.MarshaledKRB5ticket)
	if err != nil {
		t.Fatalf("Test vector read error: %v", err)
	}
	err = tkt.Unmarshal(b)
	if err != nil {
		t.Fatalf("Unmarshal error: %v", err)
	}

	key := types.EncryptionKey{
		KeyType:  18,
		KeyValue: make([]byte, 32),
	}

	mt, err := NewKRB5TokenUser2UserAPREQ(&cl, tkt, key, []int{gssapi.ContextFlagInteg, gssapi.ContextFlagConf})
	if err != nil {
		t.Fatalf("Error creating User2User KRB5Token: %v", err)
	}

	// Verify OID is User2User OID
	assert.Equal(t, gssapi.OIDKRB5User2User.OID(), mt.OID, "KRB5Token OID should be User2User OID")
	// Verify token ID is AP_REQ
	assert.Equal(t, []byte{1, 0}, mt.tokID, "TokID not as expected")
	// Verify message type is AP_REQ
	assert.Equal(t, msgtype.KRB_AP_REQ, mt.APReq.MsgType, "KRB5Token AP_REQ does not have the right message type")
	// Verify APOptionUseSessionKey is set
	assert.True(t, types.IsFlagSet(&mt.APReq.APOptions, flags.APOptionUseSessionKey), "APOptionUseSessionKey flag should be set")
	// Verify APOptionMutualRequired is set
	assert.True(t, types.IsFlagSet(&mt.APReq.APOptions, flags.APOptionMutualRequired), "APOptionMutualRequired flag should be set")
	// Verify ticket information
	assert.Equal(t, testdata.TEST_REALM, mt.APReq.Ticket.Realm, "Realm in ticket within the AP_REQ not as expected")
	assert.Equal(t, testdata.TEST_PRINCIPALNAME_NAMESTRING, mt.APReq.Ticket.SName.NameString, "SName in ticket within the AP_REQ not as expected")
	assert.Equal(t, int32(18), mt.APReq.EncryptedAuthenticator.EType, "Authenticator within AP_REQ does not have the etype expected")
}

func TestNewKRB5TokenUser2UserAPREQ_MarshalUnmarshal(t *testing.T) {
	t.Parallel()
	creds := credentials.New("hftsai", testdata.TEST_REALM)
	creds.SetCName(types.PrincipalName{NameType: nametype.KRB_NT_PRINCIPAL, NameString: testdata.TEST_PRINCIPALNAME_NAMESTRING})
	cl := client.Client{
		Credentials: creds,
	}

	var tkt messages.Ticket
	b, err := hex.DecodeString(testdata.MarshaledKRB5ticket)
	if err != nil {
		t.Fatalf("Test vector read error: %v", err)
	}
	err = tkt.Unmarshal(b)
	if err != nil {
		t.Fatalf("Unmarshal error: %v", err)
	}

	key := types.EncryptionKey{
		KeyType:  18,
		KeyValue: make([]byte, 32),
	}

	// Create token
	mt, err := NewKRB5TokenUser2UserAPREQ(&cl, tkt, key, []int{gssapi.ContextFlagInteg, gssapi.ContextFlagConf})
	if err != nil {
		t.Fatalf("Error creating User2User KRB5Token: %v", err)
	}

	// Marshal the token
	mb, err := mt.Marshal()
	if err != nil {
		t.Fatalf("Error marshalling KRB5Token: %v", err)
	}

	// Unmarshal into a new token
	var mt2 KRB5Token
	err = mt2.Unmarshal(mb)
	if err != nil {
		t.Fatalf("Error unmarshalling KRB5Token: %v", err)
	}

	// Verify the unmarshalled token has the same properties
	assert.Equal(t, gssapi.OIDKRB5User2User.OID(), mt2.OID, "Unmarshalled KRB5Token OID should be User2User OID")
	assert.Equal(t, []byte{1, 0}, mt2.tokID, "Unmarshalled TokID not as expected")
	assert.Equal(t, msgtype.KRB_AP_REQ, mt2.APReq.MsgType, "Unmarshalled KRB5Token AP_REQ does not have the right message type")
	assert.True(t, types.IsFlagSet(&mt2.APReq.APOptions, flags.APOptionUseSessionKey), "Unmarshalled APOptionUseSessionKey flag should be set")
	assert.True(t, types.IsFlagSet(&mt2.APReq.APOptions, flags.APOptionMutualRequired), "Unmarshalled APOptionMutualRequired flag should be set")
	assert.Equal(t, testdata.TEST_REALM, mt2.APReq.Ticket.Realm, "Unmarshalled realm not as expected")
	assert.Equal(t, testdata.TEST_PRINCIPALNAME_NAMESTRING, mt2.APReq.Ticket.SName.NameString, "Unmarshalled SName not as expected")
}

func TestNewKRB5TokenUser2UserAPREQ_WithDifferentFlags(t *testing.T) {
	t.Parallel()
	creds := credentials.New("hftsai", testdata.TEST_REALM)
	creds.SetCName(types.PrincipalName{NameType: nametype.KRB_NT_PRINCIPAL, NameString: testdata.TEST_PRINCIPALNAME_NAMESTRING})
	cl := client.Client{
		Credentials: creds,
	}

	var tkt messages.Ticket
	b, err := hex.DecodeString(testdata.MarshaledKRB5ticket)
	if err != nil {
		t.Fatalf("Test vector read error: %v", err)
	}
	err = tkt.Unmarshal(b)
	if err != nil {
		t.Fatalf("Unmarshal error: %v", err)
	}

	key := types.EncryptionKey{
		KeyType:  18,
		KeyValue: make([]byte, 32),
	}

	// Test with only ContextFlagInteg
	mt, err := NewKRB5TokenUser2UserAPREQ(&cl, tkt, key, []int{gssapi.ContextFlagInteg})
	if err != nil {
		t.Fatalf("Error creating User2User KRB5Token: %v", err)
	}

	// Verify U2U-specific flags are still set regardless of GSSAPI flags
	assert.True(t, types.IsFlagSet(&mt.APReq.APOptions, flags.APOptionUseSessionKey), "APOptionUseSessionKey should always be set for User2User")
	assert.True(t, types.IsFlagSet(&mt.APReq.APOptions, flags.APOptionMutualRequired), "APOptionMutualRequired should always be set for User2User")

	// Test with empty GSSAPI flags
	mt2, err := NewKRB5TokenUser2UserAPREQ(&cl, tkt, key, []int{})
	if err != nil {
		t.Fatalf("Error creating User2User KRB5Token with empty flags: %v", err)
	}

	assert.True(t, types.IsFlagSet(&mt2.APReq.APOptions, flags.APOptionUseSessionKey), "APOptionUseSessionKey should be set even with empty GSSAPI flags")
	assert.True(t, types.IsFlagSet(&mt2.APReq.APOptions, flags.APOptionMutualRequired), "APOptionMutualRequired should be set even with empty GSSAPI flags")
}

func TestNewKRB5TokenUser2UserAPREQ_IsAPReq(t *testing.T) {
	t.Parallel()
	creds := credentials.New("hftsai", testdata.TEST_REALM)
	creds.SetCName(types.PrincipalName{NameType: nametype.KRB_NT_PRINCIPAL, NameString: testdata.TEST_PRINCIPALNAME_NAMESTRING})
	cl := client.Client{
		Credentials: creds,
	}

	var tkt messages.Ticket
	b, err := hex.DecodeString(testdata.MarshaledKRB5ticket)
	if err != nil {
		t.Fatalf("Test vector read error: %v", err)
	}
	err = tkt.Unmarshal(b)
	if err != nil {
		t.Fatalf("Unmarshal error: %v", err)
	}

	key := types.EncryptionKey{
		KeyType:  18,
		KeyValue: make([]byte, 32),
	}

	mt, err := NewKRB5TokenUser2UserAPREQ(&cl, tkt, key, []int{gssapi.ContextFlagInteg})
	if err != nil {
		t.Fatalf("Error creating User2User KRB5Token: %v", err)
	}

	// Verify it's identified as an AP_REQ
	assert.True(t, mt.IsAPReq(), "Token should be identified as AP_REQ")
	assert.False(t, mt.IsAPRep(), "Token should not be identified as AP_REP")
	assert.False(t, mt.IsKRBError(), "Token should not be identified as KRBError")
	assert.False(t, mt.IsTGTReq(), "Token should not be identified as TGT_REQ")
	assert.False(t, mt.IsTGTRep(), "Token should not be identified as TGT_REP")
}
