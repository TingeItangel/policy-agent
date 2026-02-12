package types

type PolicyRequestHeader struct {
	Nonce     string `json:"nonce"`    // Unique identifier for the request to prevent replay attacks
	HashAlgo  string `json:"hashType"` // e.g. "SHA256"
	HashValue string `json:"hash"`
	HMAC      string `json:"hmac"` // e.g. "HMAC-SHA256" + base64(HMAC-SHA256( SHA256(body) + nonce , secretKey)) for authentication
}

// PolicyRequest represents the JSON payload sent by the client
type PolicyRequestBody struct {
	SessionID      string   `json:"sessionID"`      // e.g. "abc123"
	DeploymentName string   `json:"deploymentName"` // e.g. "my-deployment"
	Namespace      string   `json:"namespace"`      // e.g. "default"
	Commands       []string `json:"commands"`       // e.g. ["echo 'hello'"]
	Images         []string `json:"image"`          // e.g. ["nginx:latest"]
	Deny           bool     `json:"deny"`           // true if the image and/or commands should be denied in the new policy
}

type PolicyRequest struct {
	Header PolicyRequestHeader
	Body   PolicyRequestBody
}
