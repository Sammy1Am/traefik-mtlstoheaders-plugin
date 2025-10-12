package mtlstoheaders

import (
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/rs/zerolog/log"
	"github.com/traefik/traefik/v3/pkg/middlewares"
)

const typeName = "PassClientTLSCert"

const (
	xForwardedTLS               = "X-Forwarded-Tls-"
	xForwardedTLSClientCert     = "X-Forwarded-Tls-Client-Cert"
	xForwardedTLSClientCertInfo = "X-Forwarded-Tls-Client-Cert-Info"
)

const (
	certSeparator     = ","
	fieldSeparator    = ";"
	subFieldSeparator = ","
)

var attributeTypeNames = map[string]string{
	"0.9.2342.19200300.100.1.25": "DC", // Domain component OID - RFC 2247
}

// IssuerDistinguishedNameOptions is a struct for specifying the configuration
// for the distinguished name info of the issuer. This information is defined in
// RFC3739, section 3.1.1.
type IssuerDistinguishedNameOptions struct {
	CommonName          string
	CountryName         string
	DomainComponent     string
	LocalityName        string
	OrganizationName    string
	SerialNumber        string
	StateOrProvinceName string
}

func newIssuerDistinguishedNameOptions(info *IssuerDistinguishedNameOptions) *IssuerDistinguishedNameOptions {
	if info == nil {
		return nil
	}

	return &IssuerDistinguishedNameOptions{
		CommonName:          info.CommonName,
		CountryName:         info.CountryName,
		DomainComponent:     info.DomainComponent,
		LocalityName:        info.LocalityName,
		OrganizationName:    info.OrganizationName,
		SerialNumber:        info.SerialNumber,
		StateOrProvinceName: info.StateOrProvinceName,
	}
}

// SubjectDistinguishedNameOptions is a struct for specifying the configuration
// for the distinguished name info of the subject. This information is defined
// in RFC3739, section 3.1.2.
type SubjectDistinguishedNameOptions struct {
	CommonName             string
	CountryName            string
	DomainComponent        string
	LocalityName           string
	OrganizationName       string
	OrganizationalUnitName string
	SerialNumber           string
	StateOrProvinceName    string
}

func newSubjectDistinguishedNameOptions(info *SubjectDistinguishedNameOptions) *SubjectDistinguishedNameOptions {
	if info == nil {
		return nil
	}

	return &SubjectDistinguishedNameOptions{
		CommonName:             info.CommonName,
		CountryName:            info.CountryName,
		DomainComponent:        info.DomainComponent,
		LocalityName:           info.LocalityName,
		OrganizationName:       info.OrganizationName,
		OrganizationalUnitName: info.OrganizationalUnitName,
		SerialNumber:           info.SerialNumber,
		StateOrProvinceName:    info.StateOrProvinceName,
	}
}

// tlsClientCertificateInfo is a struct for specifying the configuration for the passTLSClientCert middleware.
type tlsClientCertificateInfo struct {
	notAfter     string
	notBefore    string
	sans         *tlsClientCertificateSans
	subject      *SubjectDistinguishedNameOptions
	issuer       *IssuerDistinguishedNameOptions
	serialNumber string
}

type tlsClientCertificateSans struct {
	dns   string
	email string
	ip    string
	uri   string
}

func newTLSClientCertificateInfo(info *tlsClientCertificateInfo) *tlsClientCertificateInfo {
	if info == nil {
		return nil
	}

	return &tlsClientCertificateInfo{
		issuer:       newIssuerDistinguishedNameOptions(info.issuer),
		notAfter:     info.notAfter,
		notBefore:    info.notBefore,
		subject:      newSubjectDistinguishedNameOptions(info.subject),
		serialNumber: info.serialNumber,
		sans:         info.sans,
	}
}

// mtlsToHeaders is a middleware that parses mTLS certificates to pass to other services.
type mtlsToHeaders struct {
	next http.Handler
	name string
	pem  string                    // pass the sanitized pem to the backend in a specific header
	info *tlsClientCertificateInfo // pass selected information from the client certificate
}

// New constructs a new mTLSToHeaders instance from supplied frontend header struct.
func New(ctx context.Context, next http.Handler, config mtlsToHeaders, name string) (http.Handler, error) {
	middlewares.GetLogger(ctx, name, typeName).Debug().Msg("Creating middleware")

	return &mtlsToHeaders{
		next: next,
		name: name,
		pem:  config.pem,
		info: newTLSClientCertificateInfo(config.info),
	}, nil
}

func (p *mtlsToHeaders) GetTracingInformation() (string, string) {
	return p.name, typeName
}

func (p *mtlsToHeaders) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	logger := middlewares.GetLogger(req.Context(), p.name, typeName)
	ctx := logger.WithContext(req.Context())

	if p.pem != "" {
		if req.TLS != nil && len(req.TLS.PeerCertificates) > 0 {
			req.Header.Set(xForwardedTLS+p.pem, strings.TrimSuffix(getCertificates(ctx, req.TLS.PeerCertificates), subFieldSeparator))
		} else {
			logger.Debug().Msg("Tried to extract a certificate on a request without mutual TLS")
		}
	}

	if p.info != nil {
		if req.TLS != nil && len(req.TLS.PeerCertificates) > 0 {
			p.extractCertInfo(ctx, req.TLS.PeerCertificates, req)
		} else {
			logger.Debug().Msg("Tried to extract a certificate on a request without mutual TLS")
		}
	}

	p.next.ServeHTTP(rw, req)
}

// extractCertInfo Writes cert info to headers
// - the `,` is used to separate values in a single field
// - if a field is empty, the field is ignored.
func (p *mtlsToHeaders) extractCertInfo(ctx context.Context, certs []*x509.Certificate, req *http.Request) {

	for _, peerCert := range certs {

		if p.info != nil {
			extractSubjectDNInfo(ctx, p.info.subject, &peerCert.Subject, req)
			extractIssuerDNInfo(ctx, p.info.issuer, &peerCert.Subject, req)

			if p.info.serialNumber != "" && peerCert.SerialNumber != nil {
				sn := peerCert.SerialNumber.String()
				if sn != "" {
					writeHeaderValue(req, p.info.serialNumber, sn)
				}
			}

			if p.info.notBefore != "" {
				writeHeaderValue(req, p.info.notBefore, fmt.Sprintf("%d", uint64(peerCert.NotBefore.Unix())))
			}

			if p.info.notAfter != "" {
				writeHeaderValue(req, p.info.notAfter, fmt.Sprintf("%d", uint64(peerCert.NotAfter.Unix())))
			}

			extractSANs(p.info.sans, peerCert, req)
		}
	}
}

func extractIssuerDNInfo(ctx context.Context, options *IssuerDistinguishedNameOptions, cs *pkix.Name, req *http.Request) {
	if options == nil {
		return
	}

	content := &strings.Builder{}

	// Manage non-standard attributes
	for _, name := range cs.Names {
		// Domain Component - RFC 2247
		if options.DomainComponent != "" && attributeTypeNames[name.Type.String()] == "DC" {
			_, _ = fmt.Fprintf(content, "DC=%s%s", name.Value, subFieldSeparator)
		}
	}

	if options.CountryName != "" {
		writeHeaderValues(req, options.CountryName, cs.Country)
	}

	if options.StateOrProvinceName != "" {
		writeHeaderValues(req, options.StateOrProvinceName, cs.Province)
	}

	if options.LocalityName != "" {
		writeHeaderValues(req, options.LocalityName, cs.Locality)
	}

	if options.OrganizationName != "" {
		writeHeaderValues(req, options.OrganizationName, cs.Organization)
	}

	if options.SerialNumber != "" {
		writeHeaderValue(req, options.SerialNumber, cs.SerialNumber)
	}

	if options.CommonName != "" {
		writeHeaderValue(req, options.CommonName, cs.CommonName)
	}
}

func extractSubjectDNInfo(ctx context.Context, options *SubjectDistinguishedNameOptions, cs *pkix.Name, req *http.Request) string {
	if options == nil {
		return ""
	}

	content := &strings.Builder{}

	// Manage non standard attributes
	for _, name := range cs.Names {
		// Domain Component - RFC 2247
		if options.DomainComponent != "" && attributeTypeNames[name.Type.String()] == "DC" {
			_, _ = fmt.Fprintf(content, "DC=%s%s", name.Value, subFieldSeparator)
		}
	}

	if options.CountryName != "" {
		writeHeaderValues(req, options.CountryName, cs.Country)
	}

	if options.StateOrProvinceName != "" {
		writeHeaderValues(req, options.StateOrProvinceName, cs.Province)
	}

	if options.LocalityName != "" {
		writeHeaderValues(req, options.LocalityName, cs.Locality)
	}

	if options.OrganizationName != "" {
		writeHeaderValues(req, options.OrganizationName, cs.Organization)
	}

	if options.OrganizationalUnitName != "" {
		writeHeaderValues(req, options.OrganizationalUnitName, cs.OrganizationalUnit)
	}

	if options.SerialNumber != "" {
		writeHeaderValue(req, options.SerialNumber, cs.SerialNumber)
	}

	if options.CommonName != "" {
		writeHeaderValue(req, options.CommonName, cs.CommonName)
	}

	return content.String()
}

func writeHeaderValue(req *http.Request, headerSuffix string, value string) {
	req.Header.Set(xForwardedTLS+headerSuffix, url.QueryEscape(strings.TrimSuffix(value, subFieldSeparator)))
}

func writeHeaderValues(req *http.Request, headerSuffix string, values []string) {
	req.Header.Set(xForwardedTLS+headerSuffix, url.QueryEscape(strings.Join(values, subFieldSeparator)))
}

// sanitize As we pass the raw certificates, remove the useless data and make it http request compliant.
func sanitize(cert []byte) string {
	return strings.NewReplacer(
		"-----BEGIN CERTIFICATE-----", "",
		"-----END CERTIFICATE-----", "",
		"\n", "",
	).Replace(string(cert))
}

// getCertificates Build a string with the client certificates.
func getCertificates(ctx context.Context, certs []*x509.Certificate) string {
	var headerValues []string

	for _, peerCert := range certs {
		headerValues = append(headerValues, extractCertificate(ctx, peerCert))
	}

	return strings.Join(headerValues, certSeparator)
}

// extractCertificate extract the certificate from the request.
func extractCertificate(ctx context.Context, cert *x509.Certificate) string {
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	if certPEM == nil {
		log.Ctx(ctx).Error().Msg("Cannot extract the certificate content")
		return ""
	}

	return sanitize(certPEM)
}

// getSANs get the Subject Alternate Name values.
func extractSANs(options *tlsClientCertificateSans, cert *x509.Certificate, req *http.Request) {
	if cert == nil {
		return
	}

	if options.dns != "" {
		writeHeaderValues(req, options.dns, cert.DNSNames)
	}

	if options.email != "" {
		writeHeaderValues(req, options.dns, cert.EmailAddresses)
	}

	if options.ip != "" {
		writeHeaderValues(req, options.dns, cert.DNSNames)
	}

	if options.uri != "" {
		writeHeaderValues(req, options.dns, cert.DNSNames)
	}

	if options.ip != "" {
		var ips []string
		for _, ip := range cert.IPAddresses {
			ips = append(ips, ip.String())
		}
		writeHeaderValues(req, options.ip, ips)
	}

	if options.uri != "" {
		var uris []string
		for _, uri := range cert.URIs {
			uris = append(uris, uri.String())
		}
		writeHeaderValues(req, options.uri, uris)
	}
}
