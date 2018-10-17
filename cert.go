package tlstest

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"time"
)

// ServerType, ClientType refers to a type of certificate
const (
	ServerType = iota
	ClientType
)

// GenCertTmpl creates new x509 certificate template being valid for an hour
func GenCertTmpl() (*x509.Certificate, error) {
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, errors.New("failed to generate serial number: " + err.Error())
	}

	tmpl := x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               pkix.Name{Organization: []string{"Yhat, Inc."}},
		SignatureAlgorithm:    x509.SHA256WithRSA,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour), // valid for an hour
		BasicConstraintsValid: true,
	}

	return &tmpl, nil
}

// GenRootCertTmpl creates new root x509 certificate template being valid for an hour
func GenRootCertTmpl() (*x509.Certificate, error) {
	tmpl, err := GenCertTmpl()
	if err != nil {
		return nil, err
	}

	tmpl.IsCA = true
	tmpl.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature
	tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}
	tmpl.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}

	return tmpl, nil
}

// GenServerCertTmpl creates new server x509 certificate template being valid for an hour
func GenServerCertTmpl() (*x509.Certificate, error) {
	tmpl, err := GenCertTmpl()
	if err != nil {
		return nil, err
	}
	tmpl.KeyUsage = x509.KeyUsageDigitalSignature
	tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	tmpl.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}

	return tmpl, nil
}

// GenClientCertTmpl creates new client x509 certificate template being valid for an hour
func GenClientCertTmpl() (*x509.Certificate, error) {
	tmpl, err := GenCertTmpl()
	if err != nil {
		return nil, err
	}
	tmpl.KeyUsage = x509.KeyUsageDigitalSignature
	tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}

	return tmpl, nil
}

// CreateCert creates a new certificate refer to a given parent cert
func CreateCert(template, parent *x509.Certificate, pub interface{}, parentPriv interface{}) (
	cert *x509.Certificate, certPEM []byte, err error) {

	certDER, err := x509.CreateCertificate(rand.Reader, template, parent, pub, parentPriv)
	if err != nil {
		return
	}

	cert, err = x509.ParseCertificate(certDER)
	if err != nil {
		return
	}

	b := pem.Block{Type: "CERTIFICATE", Bytes: certDER}
	certPEM = pem.EncodeToMemory(&b)
	return
}

// Cert stores CA certificate and its private key
type Cert struct {
	Cert    *x509.Certificate
	CertPEM []byte
	Key     *rsa.PrivateKey
	TLSCert tls.Certificate
}

// GenRootCert returns root certificate, pem (in term of []byte) and root's private key.
func GenRootCert() (root *Cert, err error) {

	rootCertTmpl, err := GenRootCertTmpl()
	if err != nil {
		return nil, fmt.Errorf("error generating certification template: %v", err)
	}

	rootKey, err := NewKey()
	if err != nil {
		return nil, fmt.Errorf("generating random key: %v", err)
	}

	cert, certPEM, err := CreateCert(rootCertTmpl, rootCertTmpl, &rootKey.PublicKey, rootKey)
	if err != nil {
		return nil, fmt.Errorf("error creating cert: %v", err)
	}

	r := Cert{
		Cert:    cert,
		CertPEM: certPEM,
		Key:     rootKey,
	}

	return &r, nil
}

// GenNormalCert returns server or client certificate, pem (in term of []byte)
// and root's private key (depended on parameter).
func GenNormalCert(certType int, CAKey *rsa.PrivateKey) (c *Cert, err error) {

	var certTmpl *x509.Certificate

	switch certType {
	case ServerType:
		certTmpl, err = GenServerCertTmpl()
	case ClientType:
		certTmpl, err = GenClientCertTmpl()
	default:
		return nil, fmt.Errorf("certificate's type is not correct")
	}

	if err != nil {
		return nil, fmt.Errorf("error generating certification template: %v", err)
	}

	key, err := NewKey()
	if err != nil {
		return nil, fmt.Errorf("generating random key: %v", err)
	}

	cert, certPEM, err := CreateCert(certTmpl, certTmpl, &key.PublicKey, CAKey)
	if err != nil {
		return nil, fmt.Errorf("error creating cert: %v", err)
	}

	// provide the private key and the cert
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key),
	})
	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("invalid key pair: %v", err)
	}

	r := Cert{
		Cert:    cert,
		CertPEM: certPEM,
		Key:     key,
		TLSCert: tlsCert,
	}

	return &r, nil
}
