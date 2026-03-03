# Policy-Agent

## Description

This project is a Kubernetes policy agent that can patch Deployments in an untrusted cluster based on requests it receives. It uses a secure communication protocol with nonce-based replay protection and integrates with a Trustee for secure session management and reference value storage.

### Challenge-Response with Nonce for Replay Protection

1. Client sends GET-Request to `/auth` endpoint to get a nonce and session ID.

```zsh
curl -k https://policy-agent:8443/auth
# Response: {"nonce":"abc123...", "sessionID":"xyz..."}
```

2. Client gets Secret Key from Trustee with session ID and uses it to sign the request body + nonce.
   - Client needs to have attested to Trustee to get access to the Secret Key.

3. Client creates a POST-Request

```zsh
body='{
  "sessionID": <sessionID>,
  "deploymentName": <deploymentName>,
  "namespace": <namespace>,
  "commands": [<command1>, <command2>],
  "image": [<image1>, <image2>],
  "deny": <true|false>,
}'

signature=<HMAC over "bodyHash.nonce"> with the Secret Key from Trustee
```

4. Client sends POST-Request to `/patch` endpoint with signed body and nonce.

```zsh
curl -k -X POST https://policy-agent:8443/patch \
  -H "Content-Type: application/json" \
  -H "X-Hash-Algorithm: SHA256" \
  -H "X-Hash-Value: <bodyHash>" \
  -H "X-Nonce: <nonce>" \
  -H "Authorization: HMAC-SHA256 <signature>" \
  -d "$body"
```

## Redis Database

- A redis instance is used to store nonces and session information for replay protection and session management.
- It has to be deployed in the Kubernetes cluster where the policy-agent is running, so that the policy-agent can access it securely (e.g. via a ClusterIP service).
- The Policy-Agent will store the session information (session ID, nonce, Secret Key) in the Trustee as well, so that it can be retrieved and verified during the patching process.

# Policy-Agent Installation

## Remote Cluster with Coco

### 1. ServiceAccount in Remote-Cluster + RBAC.

- `kubectl apply -f ./deployments/remoteCluster-rbac.yaml`
- IMPORTANT: RBAC Rules must have permissions to patch the Deployments in the target namespace, where the policy-agent patching should be allowed. The RBAC rules should be as restrictive as possible to follow the principle of least privilege.

### 2. ServiceAccount Token in Remote-Cluster

```bash
kubectl -n default create token policy-agent-sa --duration=8760h > /tmp/policy-agent-sa.token

# Example output:
cat policy-agent-sa.token
# eyJhbGciOiJSUzI1NiIsImtpZCI6IkVHUkUza3Y1YTZ6OUp6dTVHbWVFSzM2WmRMdWdPZ3V5Q1BSYzgyTFZmUWMifQ....
```

- IMPORTANT: The token file will be mounted as a secret in the policy-agent pod in the local cluster.

### 3. CA from Remote-Cluster

```bash
# Remote-Clusters CA from kubeconfig:
CLUSTER_NAME=$(kubectl config view -o jsonpath='{.contexts[?(@.name=="'$(kubectl config current-context)'")].context.cluster}')

kubectl config view --raw -o jsonpath="{.clusters[?(@.name==\"$CLUSTER_NAME\")].cluster.certificate-authority-data}" | base64 -d > /tmp/remote.ca.crt

# Example output:
cat remote.ca.crt
# -----BEGIN CERTIFICATE-----
# MIIDBTCCAe2gAwIBAgIIFZ+wWjIbNjowDQYJKoZIhvcNAQ...
# -----END CERTIFICATE-----
```

### 4. API-Server-URL from Remote-Clusters aus kubeconfig

```bash
CLUSTER_NAME=$(kubectl config view -o jsonpath='{.contexts[?(@.name=="'$(kubectl config current-context)'")].context.cluster}')

kubectl config view -o jsonpath="{.clusters[?(@.name==\"$CLUSTER_NAME\")].cluster.server}"
# Example output:
# https://<remote-cluster-ip>:6443

# or as File:
kubectl config view --raw -o jsonpath="{.clusters[?(@.name==\"$CLUSTER_NAME\")].cluster.server}" > /tmp/remote.api-server-url
```

### 5. Remote-Cluster-Deployments adjustments

- The following command must be allowed in the CoCo:

```bash
curl -s http://127.0.0.1:8006/aa/token?token_type=kbs
```

- This is needed to get the token for the API-Calls from the policy-agent pod to the Guest-CVM, which is required to patch the Deployments in the remote cluster.
  - `io.katacontainers.config.hypervisor.kernel_params: "agent.guest_components_rest_api=all"`

The initdata Annotation in the Deployment must be adapted to include the policy_data structure with the allowed commands and images, which is used by the policy-agent to determine if a patch request should be allowed or denied.

```toml
...
default CreateContainerRequest := false
default ExecProcessRequest := false

CreateContainerRequest if {
	every storage in input.storages {
        some allowed_image in policy_data.allowed_images
        storage.source == allowed_image
    }
}

ExecProcessRequest if {
    input_command = concat(" ", input.process.Args)
	some allowed_command in policy_data.allowed_commands
	input_command == allowed_command
}

policy_data := {
	"allowed_commands": [
		"curl -s http://127.0.0.1:8006/aa/token?token_type=kbs",
	],
	"allowed_images": [
		"pause",
        "nginx:latest"
	]
}
...
```

The Policy-Agent can only patch Deployments if the initdata file contains such a policy_data structure. It checks for the presence of this structure and accordingly adds/removes new commands or adjusts the image at this point.

## Local Cluster

### 1. Policy-Agent-RBAC

- Trustee-Namespace adjustment (z. B. `confidential-containers-system` or `operators`)
- `kubectl apply -f ./deployments/rbac-trusted-cluster.yaml`

### 2. Create Secrets in lokal Cluster for Policy-Agent

#### 2.1 Remote Cluster Credentials

- API-Server-URL, token and CA of remote clusters have to be stored as secrets in the local cluster, so that the policy-agent can access them to interact with the remote cluster.

```bash
# Create Secret in local cluster
kubectl -n policy-agent create secret generic remote-cluster-cred --from-file=api-server-url=/tmp/remote.api.server.url --from-file=token=/tmp/policy-agent-sa.token --from-file=ca.crt=/tmp/remote.ca.crt
```

#### 2.2 Server Certificate for TLS

```bash
kubectl create namespace policy-agent

# Certificate and Key
openssl req -x509 -newkey rsa:4096 \
  -keyout /tmp/server.key \
  -out /tmp/server.crt \
  -days 365 -nodes \
  -subj "//CN=policy-agent"

# Deploy Server Certificate and Key as Secret in local cluster
kubectl -n policy-agent create secret tls policy-agent-tls --cert=/tmp/server.crt --key=/tmp/server.key
```

#### 2.3 DockerHub Credentials (optional)

```bash
kubectl create secret docker-registry dockerhub-cred \
  --docker-server=https://index.docker.io/v1/ \
  --docker-username=<DOCKERHUB_USERNAME> \
  --docker-password='<DOCKERHUB_TOKEN_OD_PASSWORD>' \
  --docker-email='dummy@example.com' \
  --namespace=policy-agent
```

### 3. Policy-Agent-Deployment erstellen

- `kubectl apply -f ./deployments/policy-agent-deployment.yaml`
- **IMPORTANT**: `ENV` Variables must be set in the Deployment file:
  - `KBS_NAMESPACE`: namespace where trustee is deployed (e.g. `confidential-containers-system` oder `operators`)
  - `KBS_CONFIG_NAME`: name of the ConfigMap in the trustee where the reference values are stored (e.g. `policy-agent-reference-values`)
  - `REDIS_ADDR`: Redis address (e.g. `redis:6379` if using the provided Redis Deployment)
  - ... and any other necessary environment variables for the policy-agent to function properly
