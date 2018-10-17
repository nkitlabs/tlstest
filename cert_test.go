package tlstest

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"log"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"strings"
	"testing"
)

func TestNoTLSConnServer(t *testing.T) {

	root, err := GenRootCert()
	if err != nil {
		log.Fatalf("cannot generate root certificate: %v", err)
	}

	// PEM encode the private key
	rootKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(root.Key),
	})

	// Create a TLS cert using the private key and certificate
	rootTLSCert, err := tls.X509KeyPair(root.CertPEM, rootKeyPEM)
	if err != nil {
		log.Fatalf("invalid key pair: %v", err)
	}

	ok := func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("HI!")) }
	s := httptest.NewUnstartedServer(http.HandlerFunc(ok))

	// Configure the server to present the certficate we created
	s.TLS = &tls.Config{
		Certificates: []tls.Certificate{rootTLSCert},
	}

	// make a HTTPS request to the server
	s.StartTLS()
	defer s.Close()

	_, err = http.Get(s.URL)
	if !strings.HasSuffix(err.Error(), "x509: certificate signed by unknown authority") {
		t.Errorf("%v", err)
	}

}

func TestTLSServer(t *testing.T) {

	root, err := GenRootCert()
	if err != nil {
		log.Fatalf("cannot generate root certificate: %v", err)
	}

	serv, err := GenNormalCert(ServerType, root.Key)
	if err != nil {
		log.Fatalf("cannot generate server certificate: %v", err)
	}

	// create another test server and use the certificate
	ok := func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("HI!")) }
	s := httptest.NewUnstartedServer(http.HandlerFunc(ok))
	s.TLS = &tls.Config{
		Certificates: []tls.Certificate{serv.TLSCert},
	}

	// create a pool of trusted certs
	certPool := x509.NewCertPool()
	certPool.AppendCertsFromPEM(root.CertPEM)

	// configure a client to use trust those certificates
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: certPool},
		},
	}
	s.StartTLS()
	defer s.Close()
	resp, err := client.Get(s.URL)
	if err != nil {
		log.Fatalf("could not make GET request: %v", err)
	}

	dump, err := httputil.DumpResponse(resp, true)
	if err != nil {
		log.Fatalf("could not dump response: %v", err)
	}
	//
	t.Errorf("\n%s\n", dump)
}

func TestTLSClientServer(t *testing.T) {

	root, err := GenRootCert()
	if err != nil {
		log.Fatalf("cannot generate root certificate: %v", err)
	}

	serv, err := GenNormalCert(ServerType, root.Key)
	if err != nil {
		log.Fatalf("cannot generate server certificate: %v", err)
	}

	// create a pool of trusted certs
	certPool := x509.NewCertPool()
	certPool.AppendCertsFromPEM(root.CertPEM)

	// create another test server and use the certificate
	ok := func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("HI!")) }
	s := httptest.NewUnstartedServer(http.HandlerFunc(ok))
	s.TLS = &tls.Config{
		Certificates: []tls.Certificate{serv.TLSCert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    certPool,
	}

	cli, err := GenNormalCert(ClientType, root.Key)
	if err != nil {
		log.Fatalf("cannot generate client certificate: %v", err)
	}

	// configure a client to use trust those certificates
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:      certPool,
				Certificates: []tls.Certificate{cli.TLSCert},
			},
		},
	}

	s.StartTLS()
	defer s.Close()
	resp, err := client.Get(s.URL)
	if err != nil {
		log.Fatalf("could not make GET request: %v", err)
	}

	dump, err := httputil.DumpResponse(resp, true)
	if err != nil {
		log.Fatalf("could not dump response: %v", err)
	}
	//
	t.Errorf("\n%s\n", dump)
}
