package service

import (
	"time"

	"github.com/jcmturner/gokrb5/v8/credentials"
	"github.com/jcmturner/gokrb5/v8/iana/errorcode"
	"github.com/jcmturner/gokrb5/v8/iana/flags"
	"github.com/jcmturner/gokrb5/v8/messages"
	"github.com/jcmturner/gokrb5/v8/types"
)

// VerifyAPREQ verifies an AP_REQ sent to the service. Returns a boolean for if the AP_REQ is valid and the client's principal name and realm.
func VerifyAPREQ(APReq *messages.APReq, s *Settings) (bool, *credentials.Credentials, error) {
	var creds *credentials.Credentials
	ok, err := APReq.Verify(s.Keytab, s.MaxClockSkew(), s.ClientAddress(), s.KeytabPrincipal())
	if err != nil || !ok {
		return false, creds, err
	}

	if s.RequireHostAddr() && len(APReq.Ticket.DecryptedEncPart.CAddr) < 1 {
		return false, creds,
			messages.NewKRBError(APReq.Ticket.SName, APReq.Ticket.Realm, errorcode.KRB_AP_ERR_BADADDR, "ticket does not contain HostAddress values required")
	}

	// Check for replay
	rc := GetReplayCache(s.MaxClockSkew())
	if rc.IsReplay(APReq.Ticket.SName, APReq.Authenticator) {
		return false, creds,
			messages.NewKRBError(APReq.Ticket.SName, APReq.Ticket.Realm, errorcode.KRB_AP_ERR_REPEAT, "replay detected")
	}

	c := credentials.NewFromPrincipalName(APReq.Authenticator.CName, APReq.Authenticator.CRealm)
	creds = c
	creds.SetAuthTime(time.Now().UTC())
	creds.SetAuthenticated(true)
	creds.SetValidUntil(APReq.Ticket.DecryptedEncPart.EndTime)

	//PAC decoding
	if !s.disablePACDecoding {
		isPAC, pac, err := APReq.Ticket.GetPACType(s.Keytab, s.KeytabPrincipal(), s.Logger())
		if isPAC && err != nil {
			return false, creds, err
		}
		if isPAC {
			// There is a valid PAC. Adding attributes to creds
			creds.SetADCredentials(credentials.ADCredentials{
				GroupMembershipSIDs: pac.KerbValidationInfo.GetGroupMembershipSIDs(),
				LogOnTime:           pac.KerbValidationInfo.LogOnTime.Time(),
				LogOffTime:          pac.KerbValidationInfo.LogOffTime.Time(),
				PasswordLastSet:     pac.KerbValidationInfo.PasswordLastSet.Time(),
				EffectiveName:       pac.KerbValidationInfo.EffectiveName.Value,
				FullName:            pac.KerbValidationInfo.FullName.Value,
				UserID:              int(pac.KerbValidationInfo.UserID),
				PrimaryGroupID:      int(pac.KerbValidationInfo.PrimaryGroupID),
				LogonServer:         pac.KerbValidationInfo.LogonServer.Value,
				LogonDomainName:     pac.KerbValidationInfo.LogonDomainName.Value,
				LogonDomainID:       pac.KerbValidationInfo.LogonDomainID.String(),
			})
		}
	}
	return true, creds, nil
}

// VerifyUser2UserAPREQ verifies an AP_REQ sent to the service for user-to-user authentication.
// This function should be used when the APOptionUseSessionKey flag is set in the AP_REQ,
// indicating that the ticket is encrypted with the session key from the service's TGT rather
// than the service's long-term key.
//
// The service must have its TGT session key configured via Settings.TGTSessionKey() for this to work.
// Returns a boolean for if the AP_REQ is valid and the client's credentials.
func VerifyUser2UserAPREQ(APReq *messages.APReq, s *Settings) (bool, *credentials.Credentials, error) {
	var creds *credentials.Credentials

	// Check if this is a user-to-user authentication request
	if !types.IsFlagSet(&APReq.APOptions, flags.APOptionUseSessionKey) {
		return false, creds, messages.NewKRBError(APReq.Ticket.SName, APReq.Ticket.Realm, errorcode.KRB_AP_ERR_BAD_INTEGRITY, "AP_REQ does not have APOptionUseSessionKey set for user-to-user authentication")
	}

	// Get the TGT session key from settings
	sessionKey := s.TGTSessionKey()
	if sessionKey == nil {
		return false, creds, messages.NewKRBError(APReq.Ticket.SName, APReq.Ticket.Realm, errorcode.KRB_AP_ERR_NOKEY, "TGT session key not configured for user-to-user authentication")
	}

	// Verify the AP_REQ using the session key
	ok, err := APReq.VerifyUser2User(*sessionKey, s.MaxClockSkew(), s.ClientAddress())
	if err != nil || !ok {
		return false, creds, err
	}

	if s.RequireHostAddr() && len(APReq.Ticket.DecryptedEncPart.CAddr) < 1 {
		return false, creds,
			messages.NewKRBError(APReq.Ticket.SName, APReq.Ticket.Realm, errorcode.KRB_AP_ERR_BADADDR, "ticket does not contain HostAddress values required")
	}

	// Check for replay
	rc := GetReplayCache(s.MaxClockSkew())
	if rc.IsReplay(APReq.Ticket.SName, APReq.Authenticator) {
		return false, creds,
			messages.NewKRBError(APReq.Ticket.SName, APReq.Ticket.Realm, errorcode.KRB_AP_ERR_REPEAT, "replay detected")
	}

	c := credentials.NewFromPrincipalName(APReq.Authenticator.CName, APReq.Authenticator.CRealm)
	creds = c
	creds.SetAuthTime(time.Now().UTC())
	creds.SetAuthenticated(true)
	creds.SetValidUntil(APReq.Ticket.DecryptedEncPart.EndTime)

	// Note: PAC decoding is typically not performed for user-to-user authentication
	// since the ticket is encrypted with the session key, not the service's long-term key.
	// The PAC would typically be signed with keys the service doesn't have access to in U2U scenarios.

	return true, creds, nil
}
