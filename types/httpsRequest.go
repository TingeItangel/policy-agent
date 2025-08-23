package types

type PolicyHeader struct {
	HashAlgo  string `json:"hashType"`
	HashValue string `json:"hash"`
}

// PolicyRequest represents the JSON payload sent by the client
type PolicyBody struct {
	Target       string   `json:"target"`       // e.g. "my-deployment"
	Namespace    string   `json:"namespace"`    // e.g. "default"
	Commands     []string `json:"commands"`     // e.g. ["echo 'hello'"]
	Images       []string `json:"image"`        // e.g. ["nginx:latest"]
	IsDeployment bool     `json:"isDeployment"` // true if the target is a deployment
	Deny         bool     `json:"deny"`         // true if the policy is a deny policy
	Nonce        string   `json:"nonce"`        // Unique identifier for the request to prevent replay attacks
}

type PolicyRequest struct {
	Header PolicyHeader
	Body   PolicyBody
}
