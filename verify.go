package aksattest

import (
	"crypto/x509"
	"errors"
	"time"
)

var (
	// ErrKeyDescriptionMissing is an error when the appropriate
	ErrKeyDescriptionMissing = errors.New("aksattest: Android KeyStore key description extension (OID: 1.3.6.1.4.1.11129.2.1.17) was missing in the certificate")
)

// Verify verifies that the provided certificate and its chain was issued by an
// Android KeyStore system (using RootCertificates as the root of trust). This
// does not check for revocation.
func Verify(now time.Time, cert *x509.Certificate, chain []*x509.Certificate) (*KeyDescription, error) {
	return VerifyWithPool(now, cert, chain, RootCertificates)
}

// VerifyWithPool verifies that the provided certificate and its chain was
// issued by an Android KeyStore system (as provided in the root parameter).
// You should use Verify. This does not check for revocation.
func VerifyWithPool(now time.Time, cert *x509.Certificate, chain []*x509.Certificate, root *x509.CertPool) (*KeyDescription, error) {
	intermediates := x509.NewCertPool()

	for _, chainCert := range chain {
		intermediates.AddCert(chainCert)
	}

	_, err := cert.Verify(x509.VerifyOptions{
		Intermediates: intermediates,
		Roots:         root,
		CurrentTime:   now,
	})
	if nil != err {
		return nil, err
	}

	desc, err := FindKeyDescription(cert)
	if nil != err {
		return nil, err
	}

	if nil == desc {
		return nil, ErrKeyDescriptionMissing
	}

	return desc, nil
}
