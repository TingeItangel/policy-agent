package trustee

import (
	"crypto/x509"
	"errors"
	"net/http"
)

func getClientCert(r *http.Request) (*x509.Certificate, error) {

	// TODO: Implement proper client certificate retrieval
	if len(r.TLS.PeerCertificates) == 0 {
		return nil, errors.New("no client certificate provided")
	}
	return r.TLS.PeerCertificates[0], nil
}

func getClientKey(r *http.Request) (string, error) {
	//TODO: Implement proper client key retrieval
	return "", nil
}

func getServerCert(r *http.Request) (*x509.Certificate, error) {

	// TODO: Implement proper server certificate retrieval
	if len(r.TLS.PeerCertificates) == 0 {
		return nil, errors.New("no client certificate provided")
	}
	return r.TLS.PeerCertificates[0], nil
}

func getServerKey(r *http.Request) (string, error) {
	//TODO: Implement proper client key retrieval
	return "", nil
}
