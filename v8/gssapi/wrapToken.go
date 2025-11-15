package gssapi

import (
	"bytes"
	"crypto/hmac"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/jcmturner/gokrb5/v8/crypto"
	"github.com/jcmturner/gokrb5/v8/iana/keyusage"
	"github.com/jcmturner/gokrb5/v8/types"
)

// RFC 4121, section 4.2.6.2

const (
	// HdrLen is the length of the Wrap Token's header
	HdrLen = 16
	// FillerByte is a filler in the WrapToken structure
	FillerByte byte = 0xFF
)

// WrapToken flags
const (
	WrapTokenFlagSentByAcceptor = 1 << iota // Indicates sender is context acceptor
	WrapTokenFlagSealed                     // Indicates confidentiality is provided
	WrapTokenFlagAcceptorSubkey             // Subkey asserted by context acceptor
)

// WrapToken represents a GSS API Wrap token, as defined in RFC 4121.
// It contains the header fields, the payload and the checksum, and provides
// the logic for converting to/from bytes plus computing and verifying checksums
type WrapToken struct {
	// const GSS Token ID: 0x0504
	Flags byte // contains three flags: acceptor, sealed, acceptor subkey
	// const Filler: 0xFF
	EC        uint16 // checksum length. big-endian
	RRC       uint16 // right rotation count. big-endian
	SndSeqNum uint64 // sender's sequence number. big-endian
	Payload   []byte // your data! :)
	CheckSum  []byte // authenticated checksum of { payload | header }
}

// Return the 2 bytes identifying a GSS API Wrap token
func getGssWrapTokenId() *[2]byte {
	return &[2]byte{0x05, 0x04}
}

// getWrapTokenHeader builds a 16-byte header for the WrapToken
func (wt *WrapToken) getWrapTokenHeader(ec, rrc uint16) []byte {
	header := make([]byte, HdrLen)
	copy(header[0:], getGssWrapTokenId()[:])
	header[2] = wt.Flags
	header[3] = FillerByte
	binary.BigEndian.PutUint16(header[4:6], ec)
	binary.BigEndian.PutUint16(header[6:8], rrc)
	binary.BigEndian.PutUint64(header[8:16], wt.SndSeqNum)
	return header
}

// Marshal the WrapToken into a byte slice.
// The payload should have been set and the checksum computed, otherwise an error is returned.
func (wt *WrapToken) Marshal() ([]byte, error) {
	if wt.CheckSum == nil {
		return nil, errors.New("checksum has not been set")
	}
	if wt.Payload == nil {
		return nil, errors.New("payload has not been set")
	}

	bytes := wt.getWrapTokenHeader(wt.EC, wt.RRC)
	bytes = append(bytes, wt.Payload...)
	bytes = append(bytes, wt.CheckSum...)
	return bytes, nil
}

// SetCheckSum uses the passed encryption key and key usage to compute the checksum over the payload and
// the header, and sets the CheckSum field of this WrapToken.
// If the payload has not been set or the checksum has already been set, an error is returned.
func (wt *WrapToken) SetCheckSum(key types.EncryptionKey, keyUsage uint32) error {
	if wt.Payload == nil {
		return errors.New("payload has not been set")
	}
	if wt.CheckSum != nil {
		return errors.New("checksum has already been computed")
	}
	chkSum, cErr := wt.computeCheckSum(key, keyUsage)
	if cErr != nil {
		return cErr
	}
	wt.CheckSum = chkSum
	return nil
}

// ComputeCheckSum computes and returns the checksum of this token, computed using the passed key and key usage.
// Note: This will NOT update the struct's Checksum field.
func (wt *WrapToken) computeCheckSum(key types.EncryptionKey, keyUsage uint32) ([]byte, error) {
	if wt.Payload == nil {
		return nil, errors.New("cannot compute checksum with uninitialized payload")
	}
	// Build a slice containing { payload | header }
	checksumMe := make([]byte, HdrLen+len(wt.Payload))
	copy(checksumMe[0:], wt.Payload)
	copy(checksumMe[len(wt.Payload):], getChecksumHeader(wt.Flags, wt.SndSeqNum))

	encType, err := crypto.GetEtype(key.KeyType)
	if err != nil {
		return nil, err
	}
	return encType.GetChecksumHash(key.KeyValue, checksumMe, keyUsage)
}

// Build a header suitable for a checksum computation
func getChecksumHeader(flags byte, senderSeqNum uint64) []byte {
	header := make([]byte, 16)
	copy(header[0:], []byte{0x05, 0x04, flags, 0xFF, 0x00, 0x00, 0x00, 0x00})
	binary.BigEndian.PutUint64(header[8:], senderSeqNum)
	return header
}

// Verify computes the token's checksum with the provided key and usage,
// and compares it to the checksum present in the token.
// In case of any failure, (false, Err) is returned, with Err an explanatory error.
func (wt *WrapToken) Verify(key types.EncryptionKey, keyUsage uint32) (bool, error) {
	computed, cErr := wt.computeCheckSum(key, keyUsage)
	if cErr != nil {
		return false, cErr
	}
	if !hmac.Equal(computed, wt.CheckSum) {
		return false, fmt.Errorf(
			"checksum mismatch. Computed: %s, Contained in token: %s",
			hex.EncodeToString(computed), hex.EncodeToString(wt.CheckSum))
	}
	return true, nil
}

// EncryptPayload encrypts the token's payload using the provided key and key usage.
// This implements the sealed (confidentiality) mode as specified in RFC 4121 Section 4.2.4.
// The payload must be set and the checksum must not be set before calling this method.
// The sealed flag must be set in the token's Flags field.
func (wt *WrapToken) EncryptPayload(key types.EncryptionKey, keyUsage uint32) error {
	if wt.Payload == nil {
		return errors.New("payload has not been set")
	}
	if wt.CheckSum != nil {
		return errors.New("checksum has already been computed")
	}
	if wt.Flags&WrapTokenFlagSealed == 0 {
		return errors.New("token is not sealed")
	}

	hdr := wt.getWrapTokenHeader(wt.EC, 0)
	filler := bytes.Repeat([]byte{0x00}, int(wt.EC))
	payload := append(append(wt.Payload, filler...), hdr...)

	encType, err := crypto.GetEtype(key.KeyType)
	if err != nil {
		return err
	}
	_, ct, err := encType.EncryptMessage(key.KeyValue, payload, keyUsage)
	if err != nil {
		return err
	}
	rotCt := rotateRight(ct, int(wt.RRC))

	checksumLen := encType.GetHMACBitLength() / 8
	wt.Payload = rotCt[:len(rotCt)-checksumLen]
	wt.CheckSum = rotCt[len(rotCt)-checksumLen:]
	return nil
}

// DecryptPayload decrypts the token's encrypted payload using the provided key and key usage.
// This implements the sealed (confidentiality) mode as specified in RFC 4121 Section 4.2.4.
// The payload must be set (by Unmarshal) before calling this method.
// The sealed flag must be set in the token's Flags field.
func (wt *WrapToken) DecryptPayload(key types.EncryptionKey, keyUsage uint32) error {
	if len(wt.Payload) == 0 {
		return errors.New("payload has not been set, use Unmarshal first")
	}
	if wt.Flags&WrapTokenFlagSealed == 0 {
		return errors.New("token is not sealed")
	}

	encType, err := crypto.GetEtype(key.KeyType)
	if err != nil {
		return err
	}

	// For sealed tokens, the payload contains both the encrypted data and the checksum
	// First, we need to append the checksum back if it's been separated
	var ciphertext []byte
	if wt.CheckSum != nil {
		ciphertext = append(wt.Payload, wt.CheckSum...)
	} else {
		ciphertext = wt.Payload
	}

	decryptedPayload, err := encType.DecryptMessage(key.KeyValue, ciphertext, keyUsage)
	if err != nil {
		return err
	}

	plaintextLen := len(decryptedPayload) - int(wt.EC) - HdrLen
	if plaintextLen < 0 {
		return fmt.Errorf("invalid decrypted data, trailing filler and header are larger than the decrypted data")
	}
	wt.Payload = decryptedPayload[:plaintextLen]
	wt.CheckSum = nil
	return nil
}

// Unmarshal bytes into the corresponding WrapToken.
// If expectFromAcceptor is true, we expect the token to have been emitted by the gss acceptor,
// and will check the according flag, returning an error if the token does not match the expectation.
func (wt *WrapToken) Unmarshal(b []byte, expectFromAcceptor bool) error {
	// Check if we can read a whole header
	if len(b) < 16 {
		return errors.New("bytes shorter than header length")
	}
	// Is the Token ID correct?
	if !bytes.Equal(getGssWrapTokenId()[:], b[0:2]) {
		return fmt.Errorf("wrong Token ID. Expected %s, was %s",
			hex.EncodeToString(getGssWrapTokenId()[:]),
			hex.EncodeToString(b[0:2]))
	}
	// Check the acceptor flag
	flags := b[2]
	isFromAcceptor := flags&0x01 == 1
	if isFromAcceptor && !expectFromAcceptor {
		return errors.New("unexpected acceptor flag is set: not expecting a token from the acceptor")
	}
	if !isFromAcceptor && expectFromAcceptor {
		return errors.New("expected acceptor flag is not set: expecting a token from the acceptor, not the initiator")
	}
	// Check the filler byte
	if b[3] != FillerByte {
		return fmt.Errorf("unexpected filler byte: expecting 0xFF, was %s ", hex.EncodeToString(b[3:4]))
	}
	checksumL := binary.BigEndian.Uint16(b[4:6])
	// Sanity check on the checksum length
	if int(checksumL) > len(b)-HdrLen {
		return fmt.Errorf("inconsistent checksum length: %d bytes to parse, checksum length is %d", len(b), checksumL)
	}

	wt.Flags = flags
	wt.EC = checksumL
	wt.RRC = binary.BigEndian.Uint16(b[6:8])
	wt.SndSeqNum = binary.BigEndian.Uint64(b[8:16])
	if wt.Flags&WrapTokenFlagSealed == 0 {
		// Unsealed token - payload and checksum are separate
		wt.Payload = b[HdrLen : len(b)-int(checksumL)]
		wt.CheckSum = b[len(b)-int(checksumL):]
	} else {
		// Sealed token - payload and checksum are rotated together
		// Left-rotate the payload and checksum by RRC bits
		// RFC 4121 Section 4.2.5
		encryptedPayloadAndChecksum := rotateLeft(b[HdrLen:], int(wt.RRC))
		// We don't know the size of the checksum yet, as it depends on the encryption type,
		// so we just assign the payload. DecryptPayload will extract the plaintext.
		wt.Payload = encryptedPayloadAndChecksum
		wt.CheckSum = nil
	}
	return nil
}

// NewInitiatorWrapToken builds a new initiator token (acceptor flag will be set to 0) and computes the authenticated checksum.
// Other flags are set to 0, and the RRC and sequence number are initialized to 0.
// Note that in certain circumstances you may need to provide a sequence number that has been defined earlier.
// This is currently not supported.
func NewInitiatorWrapToken(payload []byte, key types.EncryptionKey) (*WrapToken, error) {
	encType, err := crypto.GetEtype(key.KeyType)
	if err != nil {
		return nil, err
	}

	token := WrapToken{
		Flags: 0x00, // all zeroed out (this is a token sent by the initiator)
		// Checksum size: length of output of the HMAC function, in bytes.
		EC:        uint16(encType.GetHMACBitLength() / 8),
		RRC:       0,
		SndSeqNum: 0,
		Payload:   payload,
	}

	if err := token.SetCheckSum(key, keyusage.GSSAPI_INITIATOR_SEAL); err != nil {
		return nil, err
	}

	return &token, nil
}

// NewInitiatorEncryptedWrapToken builds a new initiator token with encryption (sealed flag set).
// The token is encrypted using the provided key and key usage.
// The acceptor flag will be set to 0, RRC and sequence number are initialized to 0.
// Note that in certain circumstances you may need to provide a sequence number that has been defined earlier.
// This is currently not supported.
func NewInitiatorEncryptedWrapToken(payload []byte, key types.EncryptionKey) (*WrapToken, error) {
	encType, err := crypto.GetEtype(key.KeyType)
	if err != nil {
		return nil, err
	}

	token := WrapToken{
		Flags:     WrapTokenFlagSealed, // set sealed flag for encryption
		EC:        uint16(encType.GetHMACBitLength() / 8),
		RRC:       0,
		SndSeqNum: 0,
		Payload:   payload,
	}

	if err := token.EncryptPayload(key, keyusage.GSSAPI_INITIATOR_SEAL); err != nil {
		return nil, err
	}

	return &token, nil
}

// rotateRight performs a right rotation of the byte slice by n positions.
// This is used for RRC (Right Rotation Count) as specified in RFC 4121.
func rotateRight(s []byte, n int) []byte {
	if n == 0 {
		return s
	}
	n = n % len(s)
	return append(s[len(s)-n:], s[:len(s)-n]...)
}

// rotateLeft performs a left rotation of the byte slice by n positions.
// This is used for RRC (Right Rotation Count) as specified in RFC 4121.
func rotateLeft(s []byte, n int) []byte {
	if n == 0 {
		return s
	}
	n = n % len(s)
	return append(s[n:], s[:n]...)
}
