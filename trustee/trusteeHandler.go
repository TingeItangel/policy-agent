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

func PatchReferenceValues() error {
	// TODO: make a https request with signitare and nonce to patch-agent
	// Load current reference values from trustee for the deployment
	// Find register of the initdata in the measurement
	// replace the initdata hash with the new one
	// save the new configmap in k8s cluster to update the trustee
	return nil
}

func createNewMeasurement(initdata string) error {
	// TODO: create new measurement with initdata to get new ref values
	return nil
}
