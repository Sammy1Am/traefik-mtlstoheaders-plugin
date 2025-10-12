package mtlstoheaders

import (
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/rs/zerolog/log"
	"github.com/traefik/traefik/v3/pkg/middlewares"
)

const typeName = "PassClientTLSCert"

const (
	xForwardedTLS     = "X-Forwarded-Tls-"
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
	sans         string
	subject      *SubjectDistinguishedNameOptions
	issuer       *IssuerDistinguishedNameOptions
	serialNumber string
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
			req.Header.Set(xForwardedTLS+p.pem, getCertificates(ctx, req.TLS.PeerCertificates))
		} else {
			logger.Debug().Msg("Tried to extract a certificate on a request without mutual TLS")
		}
	}

	if p.info != nil {
		if req.TLS != nil && len(req.TLS.PeerCertificates) > 0 {
			headerContent := p.getCertInfo(ctx, req.TLS.PeerCertificates)
			req.Header.Set(xForwardedTLSClientCertInfo, url.QueryEscape(headerContent))
		} else {
			logger.Debug().Msg("Tried to extract a certificate on a request without mutual TLS")
		}
	}

	p.next.ServeHTTP(rw, req)
}

// getCertInfo Build a string with the wanted client certificates information
// - the `,` is used to separate certificates
// - the `;` is used to separate root fields
// - the value of root fields is always wrapped by double quote
// - if a field is empty, the field is ignored.
func (p *mtlsToHeaders) getCertInfo(ctx context.Context, certs []*x509.Certificate) string {
	var headerValues []string

	for _, peerCert := range certs {
		var values []string

		if p.info != nil {
			subject := getSubjectDNInfo(ctx, p.info.subject, &peerCert.Subject)
			if subject != "" {
				values = append(values, fmt.Sprintf(`Subject="%s"`, strings.TrimSuffix(subject, subFieldSeparator)))
			}

			issuer := getIssuerDNInfo(ctx, p.info.issuer, &peerCert.Issuer)
			if issuer != "" {
				values = append(values, fmt.Sprintf(`Issuer="%s"`, strings.TrimSuffix(issuer, subFieldSeparator)))
			}

			if p.info.serialNumber != "" && peerCert.SerialNumber != nil {
				sn := peerCert.SerialNumber.String()
				if sn != "" {
					values = append(values, fmt.Sprintf(`SerialNumber="%s"`, strings.TrimSuffix(sn, subFieldSeparator)))
				}
			}

			if p.info.notBefore != "" {
				values = append(values, fmt.Sprintf(`NB="%d"`, uint64(peerCert.NotBefore.Unix())))
			}

			if p.info.notAfter != "" {
				values = append(values, fmt.Sprintf(`NA="%d"`, uint64(peerCert.NotAfter.Unix())))
			}

			if p.info.sans != "" {
				sans := getSANs(peerCert)
				if len(sans) > 0 {
					values = append(values, fmt.Sprintf(`SAN="%s"`, strings.Join(sans, subFieldSeparator)))
				}
			}
		}

		value := strings.Join(values, fieldSeparator)
		headerValues = append(headerValues, value)
	}

	return strings.Join(headerValues, certSeparator)
}

func getIssuerDNInfo(ctx context.Context, options *IssuerDistinguishedNameOptions, cs *pkix.Name) string {
	if options == nil {
		return ""
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
		writeParts(ctx, content, cs.Country, "C")
	}

	if options.StateOrProvinceName != "" {
		writeParts(ctx, content, cs.Province, "ST")
	}

	if options.LocalityName != "" {
		writeParts(ctx, content, cs.Locality, "L")
	}

	if options.OrganizationName != "" {
		writeParts(ctx, content, cs.Organization, "O")
	}

	if options.SerialNumber != "" {
		writePart(ctx, content, cs.SerialNumber, "SN")
	}

	if options.CommonName != "" {
		writePart(ctx, content, cs.CommonName, "CN")
	}

	return content.String()
}

func getSubjectDNInfo(ctx context.Context, options *SubjectDistinguishedNameOptions, cs *pkix.Name) string {
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
		writeParts(ctx, content, cs.Country, "C")
	}

	if options.StateOrProvinceName != "" {
		writeParts(ctx, content, cs.Province, "ST")
	}

	if options.LocalityName != "" {
		writeParts(ctx, content, cs.Locality, "L")
	}

	if options.OrganizationName != "" {
		writeParts(ctx, content, cs.Organization, "O")
	}

	if options.OrganizationalUnitName != "" {
		writeParts(ctx, content, cs.OrganizationalUnit, "OU")
	}

	if options.SerialNumber != "" {
		writePart(ctx, content, cs.SerialNumber, "SN")
	}

	if options.CommonName != "" {
		writePart(ctx, content, cs.CommonName, "CN")
	}

	return content.String()
}

func writeParts(ctx context.Context, content io.StringWriter, entries []string, prefix string) {
	for _, entry := range entries {
		writePart(ctx, content, entry, prefix)
	}
}

func writePart(ctx context.Context, content io.StringWriter, entry, prefix string) {
	if len(entry) > 0 {
		_, err := content.WriteString(fmt.Sprintf("%s=%s%s", prefix, entry, subFieldSeparator))
		if err != nil {
			log.Ctx(ctx).Error().Err(err).Send()
		}
	}
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
func getSANs(cert *x509.Certificate) []string {
	if cert == nil {
		return nil
	}

	var sans []string
	sans = append(sans, cert.DNSNames...)
	sans = append(sans, cert.EmailAddresses...)

	for _, ip := range cert.IPAddresses {
		sans = append(sans, ip.String())
	}

	for _, uri := range cert.URIs {
		sans = append(sans, uri.String())
	}

	return sans
}