package tlstest

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"log"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
)

func ExampleCreateCert() {
	rootCertTmpl, err := GenRootCertTmpl()
	if err != nil {
		log.Fatalf("error generating certification template: %v", err)
	}

	rootKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatalf("generating random key: %v", err)
	}

	ssCert, ssCertPEM, err := CreateCert(rootCertTmpl, rootCertTmpl, &rootKey.PublicKey, rootKey)
	if err != nil {
		log.Fatalf("error creating cert: %v", err)
	}
	log.Printf("%s\n", ssCertPEM)
	log.Printf("%#x\n", ssCert.Signature) // more ugly binary

}

func ExampleServerTLSConnection() {

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
	log.Printf("\n%s\n", dump)
}

func ExampleClientServerTLSConnection() {

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
	log.Printf("\n%s\n", dump)
}
