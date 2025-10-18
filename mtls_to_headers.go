package traefik_mtlstoheaders_plugin

import (
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

const (
	xForwardedTLS = "X-Forwarded-Tls-"
)

const (
	certSeparator     = ","
	subFieldSeparator = ","
)

// Config the plugin configuration.
type Config struct {
	PEM  string                    `json:"pem,omitempty"`
	Info *tlsClientCertificateInfo `json:"info,omitempty"`
}

type tlsClientCertificateInfo struct {
	NotAfter     string                           `json:"notAfter,omitempty"`
	NotBefore    string                           `json:"notBefore,omitempty"`
	SerialNumber string                           `json:"serialNumber,omitempty"`
	Subject      *SubjectDistinguishedNameOptions `json:"subject,omitempty"`
	Issuer       *IssuerDistinguishedNameOptions  `json:"issuer,omitempty"`
	SANS         *tlsClientCertificateSans        `json:"sans,omitempty"`
}

// IssuerDistinguishedNameOptions is a struct for specifying the configuration
// for the distinguished name info of the issuer. This information is defined in
// RFC3739, section 3.1.1.
type IssuerDistinguishedNameOptions struct {
	CommonName          string `json:"commonName,omitempty"`
	CountryName         string `json:"country,omitempty"`
	DomainComponent     string `json:"domainComponent,omitempty"`
	LocalityName        string `json:"locality,omitempty"`
	OrganizationName    string `json:"organization,omitempty"`
	SerialNumber        string `json:"serialNumber,omitempty"`
	StateOrProvinceName string `json:"province,omitempty"`
}

// SubjectDistinguishedNameOptions is a struct for specifying the configuration
// for the distinguished name info of the subject. This information is defined
// in RFC3739, section 3.1.2.
type SubjectDistinguishedNameOptions struct {
	CommonName             string `json:"commonName,omitempty"`
	CountryName            string `json:"country,omitempty"`
	DomainComponent        string `json:"domainComponent,omitempty"`
	LocalityName           string `json:"locality,omitempty"`
	OrganizationName       string `json:"organization,omitempty"`
	OrganizationalUnitName string `json:"organizationalUnit,omitempty"`
	SerialNumber           string `json:"serialNumber,omitempty"`
	StateOrProvinceName    string `json:"province,omitempty"`
}

type tlsClientCertificateSans struct {
	DNS   string `json:"dns,omitempty"`
	Email string `json:"email,omitempty"`
	Ip    string `json:"ip,omitempty"`
	URI   string `json:"uri,omitempty"`
}

// CreateConfig creates the default plugin configuration.
func CreateConfig() *Config {
	return &Config{}
}

// Demo a Demo plugin.
type MTLSToHeaders struct {
	next http.Handler
	name string
	pem  string
	info *tlsClientCertificateInfo
}

// New created a new Demo plugin.
func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	if len(config.PEM) == 0 {
		return nil, fmt.Errorf("headers cannot be empty")
	}

	return &MTLSToHeaders{
		pem:  config.PEM,
		info: config.Info,
		next: next,
		name: name,
	}, nil
}

func (p *MTLSToHeaders) ServeHTTP(rw http.ResponseWriter, req *http.Request) {

	if p.pem != "" {
		if req.TLS != nil && len(req.TLS.PeerCertificates) > 0 {
			req.Header.Set(xForwardedTLS+p.pem, strings.TrimSuffix(getCertificates(req.TLS.PeerCertificates), subFieldSeparator))
		} else {
			//log.Print("Tried to extract a certificate on a request without mutual TLS")
		}
	}
	if p.info != nil {
		if req.TLS != nil && len(req.TLS.PeerCertificates) > 0 {
			p.extractCertInfo(req.TLS.PeerCertificates, req)
		} else {
			//log.Print("Tried to extract a certificate on a request without mutual TLS")
		}
	}

	req.Header.Set("Test", "Success!")

	p.next.ServeHTTP(rw, req)
}

func writeHeaderValue(req *http.Request, headerSuffix string, value string) {
	req.Header.Set(xForwardedTLS+headerSuffix, url.QueryEscape(strings.TrimSuffix(value, subFieldSeparator)))
}

func writeHeaderValues(req *http.Request, headerSuffix string, values []string) {
	//log.Printf("Invalues")
	req.Header.Set(xForwardedTLS+headerSuffix, url.QueryEscape(strings.Join(values, subFieldSeparator)))
	//log.Printf("Done values")
}

// getCertificates Build a string with the client certificates.
func getCertificates(certs []*x509.Certificate) string {
	var headerValues []string

	for _, peerCert := range certs {
		headerValues = append(headerValues, extractCertificate(peerCert))
	}

	return strings.Join(headerValues, certSeparator)
}

// extractCertificate extract the certificate from the request.
func extractCertificate(cert *x509.Certificate) string {
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	if certPEM == nil {
		//log.Print("Cannot extract the certificate content")
		return ""
	}

	return sanitize(certPEM)
}

// sanitize As we pass the raw certificates, remove the useless data and make it http request compliant.
func sanitize(cert []byte) string {
	return strings.NewReplacer(
		"-----BEGIN CERTIFICATE-----", "",
		"-----END CERTIFICATE-----", "",
		"\n", "",
	).Replace(string(cert))
}

// extractCertInfo Writes cert info to headers
// - the `,` is used to separate values in a single field
// - if a field is empty, the field is ignored.
func (p *MTLSToHeaders) extractCertInfo(certs []*x509.Certificate, req *http.Request) {
	for _, peerCert := range certs {
		if p.info.SerialNumber != "" && peerCert.SerialNumber != nil {
			sn := peerCert.SerialNumber.String()
			if sn != "" {
				writeHeaderValue(req, p.info.SerialNumber, sn)
			}
		}

		if p.info.NotBefore != "" {
			writeHeaderValue(req, p.info.NotBefore, fmt.Sprintf("%d", uint64(peerCert.NotBefore.Unix())))
		}

		if p.info.NotAfter != "" {
			writeHeaderValue(req, p.info.NotAfter, fmt.Sprintf("%d", uint64(peerCert.NotAfter.Unix())))
		}

		if p.info != nil && p.info.Subject != nil {
			extractSubjectDNInfo(p.info.Subject, &peerCert.Subject, req)
		}

		if p.info != nil && p.info.Issuer != nil {
			extractIssuerDNInfo(p.info.Issuer, &peerCert.Issuer, req)
		}

		if p.info != nil && p.info.SANS != nil {
			extractSANs(p.info.SANS, peerCert, req)
		}

	}
}

func extractSubjectDNInfo(options *SubjectDistinguishedNameOptions, cs *pkix.Name, req *http.Request) {
	if options == nil {
		return
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
}

func extractIssuerDNInfo(options *IssuerDistinguishedNameOptions, cs *pkix.Name, req *http.Request) {
	if options == nil {
		return
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

// getSANs get the Subject Alternate Name values.
func extractSANs(options *tlsClientCertificateSans, cert *x509.Certificate, req *http.Request) {
	if cert == nil {
		return
	}
	if options.DNS != "" {
		writeHeaderValues(req, options.DNS, cert.DNSNames)
	}

	if options.Email != "" {
		writeHeaderValues(req, options.Email, cert.EmailAddresses)
	}

	if options.Ip != "" {
		var ips []string
		for _, ip := range cert.IPAddresses {
			ips = append(ips, ip.String())
		}
		writeHeaderValues(req, options.Ip, ips)
	}

	if options.URI != "" {
		var uris []string
		for _, uri := range cert.URIs {
			uris = append(uris, uri.String())
		}
		writeHeaderValues(req, options.URI, uris)
	}
}
