package aksattest

import (
	"crypto/x509"
	"encoding/asn1"
	"fmt"
)

var (
	// KeyDescriptionOID holds the ASN.1 OID 1.3.6.1.4.1.11129.2.1.17 for the Android KeyStore X509
	// certificate extension as described in
	// https://source.android.com/security/keystore/attestation and
	// https://android.googlesource.com/platform/hardware/interfaces/+/master/keymaster/4.0/support/include/keymasterV4_0/attestation_record.h#43.
	KeyDescriptionOID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 1, 17}
)

// RootOfTrust is a part of the KeyDescription structure.
type RootOfTrust struct {
	VerifiedBootKey   []byte
	DeviceLocked      bool
	VerifiedBootState asn1.Enumerated `asn1:"default:3"`
	VerifiedBootHash  []byte
}

// AttestationPackageInfo is a part of the KeyDescription structure.
type AttestationApplicationID struct {
	PackageInfos     []AttestationPackageInfo `asn1:"set"`
	SignatureDigests [][]byte                 `asn1:"set"`
}

// AttestationPackageInfo is a part of the KeyDescription structure.
type AttestationPackageInfo struct {
	PackageName []byte
	Version     int
}

// AuthorizationList is a part of the KeyDescription structure. Find more info
// about it at
// https://source.android.com/security/keystore/attestation#authorizationlist-fields.
// Additional information may be useful at
// https://source.android.com/security/keystore/tags.
type AuthorizationList struct {
	Purpose                     []int           `asn1:"explicit,optional,set,tag:1"`
	Algorithm                   int             `asn1:"explicit,optional,tag:2"`
	KeySize                     int             `asn1:"explicit,optional,tag:3"`
	Digest                      []int           `asn1:"explicit,optional,set,tag:5"`
	Padding                     []int           `asn1:"explicit,optional,set,tag:6"`
	ECCurve                     int             `asn1:"explicit,optional,tag:10"`
	RSAPublicExponent           int64           `asn1:"explicit,optional,tag:200"`
	RollbackResistance          []byte          `asn1:"explicit,optional,tag:303"`
	ActiveDateTime              int64           `asn1:"explicit,optional,tag:400"`
	OriginationExpireDateTime   int64           `asn1:"explicit,optional,tag:401"`
	UsageExpireDateTime         int64           `asn1:"explicit,optional,tag:402"`
	NoAuthRequired              []byte          `asn1:"explicit,optional,tag:503"`
	UserAuthType                int             `asn1:"explicit,optional,tag:504"`
	AuthTimeout                 int             `asn1:"explicit,optional,tag:505"`
	AllowWhileOnBody            []byte          `asn1:"explicit,optional,tag:506"`
	TrustedUserPresenceRequired []byte          `asn1:"explicit,optional,tag:507"`
	TrustedConfirmationRequired []byte          `asn1:"explicit,optional,tag:508"`
	UnlockedDeviceRequired      []byte          `asn1:"explicit,optional,tag:509"`
	AllApplications             []byte          `asn1:"explicit,optional,tag:600"`
	ApplicationID               []byte          `asn1:"explicit,optional,tag:601"`
	CreationDateTime            int64           `asn1:"explicit,optional,tag:701"`
	Origin                      int             `asn1:"explicit,optional,tag:702"`
	RootOfTrust                 asn1.Enumerated `asn1:"explicit,optional,tag:704"`
	OSVersion                   int             `asn1:"explicit,optional,tag:705"`
	OSPatchLevel                int             `asn1:"explicit,optional,tag:706"`
	AttestationApplicationID    []byte          `asn1:"explicit,optional,tag:709"`
	Brand                       []byte          `asn1:"explicit,optional,tag:710"`
	Device                      []byte          `asn1:"explicit,optional,tag:711"`
	Product                     []byte          `asn1:"explicit,optional,tag:712"`
	Serial                      []byte          `asn1:"explicit,optional,tag:713"`
	IMEI                        []byte          `asn1:"explicit,optional,tag:714"`
	MEID                        []byte          `asn1:"explicit,optional,tag:715"`
	Manufacturer                []byte          `asn1:"explicit,optional,tag:716"`
	Model                       []byte          `asn1:"explicit,optional,tag:717"`
	VendorPatchLevel            int             `asn1:"explicit,optional,tag:718"`
	BootPatchLevel              int             `asn1:"explicit,optional,tag:719"`
}

// KeyDescription represents the Android KeyStore attestation extension
// content. Find more information at
// https://source.android.com/security/keystore/attestation#schema.
type KeyDescription struct {
	AttestationVersion       int               `asn1:"optional"`
	AttestationSecurityLevel asn1.Enumerated   `asn1:"optional"`
	KeymasterVersion         int               `asn1:"optional"`
	KeymasterSecurityLevel   asn1.Enumerated   `asn1:"optional"`
	AttestationChallenge     []byte            `asn1:"optional"`
	UniqueID                 []byte            `asn1:"optional"`
	SoftwareEnforced         AuthorizationList `asn1:"optional"`
	TeeEnforced              AuthorizationList `asn1:"optional"`
}

// ErrKeyDescriptionInvalid describes an error where the Android KeyStore
// extension exists in a certificate but has failed parsing. Inspect the Cause
// field for the cause.
type ErrKeyDescriptionInvalid struct {
	Cause error
}

func (e *ErrKeyDescriptionInvalid) Error() string {
	return fmt.Sprintf("aksattest: Key description was not valid: %v", e.Cause.Error())
}

// FindKeyDescription finds the Android KeyStore extension in the certificate
// and parses it.  If the parsing fails, the error would be
// ErrKeyDescriptionInvalid.
func FindKeyDescription(cert *x509.Certificate) (*KeyDescription, error) {
	for _, ext := range cert.Extensions {
		if KeyDescriptionOID.Equal(ext.Id) {
			desc := &KeyDescription{}
			_, err := asn1.Unmarshal(ext.Value, desc)
			if nil != err {
				return nil, &ErrKeyDescriptionInvalid{
					Cause: err,
				}
			}

			return desc, nil
		}
	}

	return nil, nil
}
