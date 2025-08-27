package trustee

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"
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
func SetRefValue(rvpsURL string, newInitDataToml string) error {
	// Build the reference value JSON payload
	rvPayload := map[string]interface{}{
		"version": "0.1.0",
		"type":    "policy",
		"payload": base64.StdEncoding.EncodeToString([]byte(newInitDataToml)),
	}

	jsonPayload, err := json.Marshal(rvPayload)
	if err != nil {
		return fmt.Errorf("failed to marshal ref value: %w", err)
	}

	req, err := http.NewRequest("POST", rvpsURL+"/register", bytes.NewBuffer(jsonPayload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("RVPS update failed: %s", string(body))
	}

	return nil
}

func GetRefValues(rvpsURL string) (map[string][]string, error) {
	resp, err := http.Get(rvpsURL + "/reference-values") // Adjust the path if needed
	if err != nil {
		return nil, fmt.Errorf("failed to query RVPS: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("RVPS returned error: %s", string(body))
	}

	var result map[string][]string
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to parse RVPS response: %w", err)
	}

	return result, nil
}
