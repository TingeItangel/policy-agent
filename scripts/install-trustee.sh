# Install docker
sudo apt install docker.io -y

# Docker ppa for containerd.io
sudo curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
sudo chmod a+r /etc/apt/keyrings/docker.asc
echo   "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu \
     $(. /etc/os-release && echo "${UBUNTU_CODENAME:-$VERSION_CODENAME}") stable" |   sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
sudo apt update
sudo apt install containerd.io -y

# Containerd config
sudo containerd config default | sudo tee /etc/containerd/config.toml > /dev/null
# Linux with systemd needs to add `SystemdCgroup = true in /etc/containerd/config.toml with runc` https://kubernetes.io/docs/setup/production-environment/container-runtimes/#containerd-systemd
sudo sed -i 's/SystemdCgroup = false/SystemdCgroup = true/' /etc/containerd/config.toml

sudo systemctl daemon-reload
sudo systemctl enable --now containerd

# Kubernetes
sudo apt install -y apt-transport-https ca-certificates curl gnupg
curl -fsSL https://pkgs.k8s.io/core:/stable:/v1.32/deb/Release.key | sudo gpg --dearmor -o /etc/apt/keyrings/kubernetes-apt-keyring.gpg
sudo chmod 644 /etc/apt/keyrings/kubernetes-apt-keyring.gpg # allow unprivileged APT programs to read this keyring
echo 'deb [signed-by=/etc/apt/keyrings/kubernetes-apt-keyring.gpg] https://pkgs.k8s.io/core:/stable:/v1.32/deb/ /' | sudo tee /etc/apt/sources.list.d/kubernetes.list
sudo chmod 644 /etc/apt/sources.list.d/kubernetes.list   # helps tools such as command-not-found to work correctly
sudo apt update
sudo apt install kubectl kubeadm kubelet -y

sudo systemctl restart containerd

# Settings for Flannel
sudo swapoff -a # Kubernetes dont like swap
cat <<EOF | sudo tee /etc/sysctl.d/k8s.conf
    net.ipv4.ip_forward = 1
EOF
sudo modprobe br_netfilter

# Setup Cluster
sudo kubeadm init --pod-network-cidr 10.244.0.0/16
mkdir -p $HOME/.kube
sudo cp -i /etc/kubernetes/admin.conf $HOME/.kube/config
sudo chown $(id -u):$(id -g) $HOME/.kube/config

# Switch to this cluster
export KUBECONFIG=$HOME/.kube/config

kubectl get pods --all-namespaces

# Container Network Interfac: Without a CNI plugin, pods cannot reach each other - not even on the same node. 
kubectl apply -f https://github.com/flannel-io/flannel/releases/latest/download/kube-flannel.yml

# Needed to schedule other pods on the single node https://kubernetes.io/docs/setup/production-environment/tools/kubeadm/create-cluster-kubeadm/#control-plane-node-isolation
kubectl taint nodes --all node-role.kubernetes.io/control-plane-


# Install Trustee from gtihub operator-trustee (https://github.com/confidential-containers/trustee-operator)
git clone https://github.com/confidential-containers/trustee-operator.git
cd trustee-operator
make deploy IMG=quay.io/confidential-containers/trustee-operator:latest
cd config/samples/all-in-one
## create authentication keys
openssl genpkey -algorithm ed25519 > privateKey
openssl pkey -in privateKey -pubout -out kbs.pem
## create all the needed resources 
## Changing in config files:
### kbs-config.yaml:
apiVersion: v1
kind: ConfigMap
metadata:
  name: kbs-config
  namespace: trustee-operator-system
data:
  kbs-config.toml: |
    [http_server]
    sockets = ["0.0.0.0:8080"]
    insecure_http = true
    private_key = "/etc/https-key/https.key"
    certificate = "/etc/https-cert/https.crt"

    [admin]
    insecure_api = true
    auth_public_key = "/etc/auth-secret/kbs.pem"

    [attestation_token]
    insecure_key = true

    [attestation_service]
    type = "coco_as_builtin"
    work_dir = "/opt/confidential-containers/attestation-service"
    policy_engine = "opa"

      [attestation_service.attestation_token_broker]
      type = "Ear"
      policy_dir = "/opt/confidential-containers/attestation-service/policies"
      
      [attestation_service.attestation_token_config]
      duration_min = 5

      [attestation_service.rvps_config]
      type = "BuiltIn"
      
        [attestation_service.rvps_config.storage]
        type = "LocalJson"
        file_path = "/opt/confidential-containers/rvps/reference-values/reference-values.json"

    [[plugins]]
    name = "resource"
    type = "LocalFs"
    dir_path = "/opt/confidential-containers/kbs/repository"

    [policy_engine]
    policy_path = "/opt/confidential-containers/opa/policy.rego"


## Reference values of Sample Attestation for Testing. If real TEE HW is used, these values need to be replaced with actual measurements.
kubectl apply -k .

## The default installation creates a sample K8s secret named kbsres1 to be made available to clients. Take a look at patch-kbs-resources.yaml and update it with the K8s secrets that you want to deliver to clients via Trustee.
## Generate self-signed certificate for KBS
cat << EOF > kbs-service-509.conf
[req]
default_bits       = 2048
default_keyfile    = localhost.key
distinguished_name = req_distinguished_name
req_extensions     = req_ext
x509_extensions    = v3_ca

[req_distinguished_name]
countryName                 = DE
countryName_default         = UK
stateOrProvinceName         = Germany
stateOrProvinceName_default = England
localityName                = Giessen
localityName_default        = Bristol
organizationName            = THM
organizationName_default    = Red Hat
organizationalUnitName      = Development
organizationalUnitName_default = Development
commonName                  = kbs-service
commonName_default          = kbs-service
commonName_max              = 64

[req_ext]
subjectAltName = @alt_names

[v3_ca]
subjectAltName = @alt_names

[alt_names]
DNS.1   = kbs-service
IP.1 = <CLUSTER_IP>
EOF
# Create secret for self-signed certificate:
openssl req -x509 -nodes -newkey rsa:2048 \
  -keyout https.key -out https.crt \
  -days 365 \
  -subj "/CN=kbs-service" \
  -config kbs-service-509.conf
# Create Kubernetes secrets for the self-signed certificate and key
kubectl create secret generic kbs-https-certificate --from-file=https.crt -n trustee-operator-system
kubectl create secret generic kbs-https-key --from-file=https.key -n trustee-operator-system

## Adjust config files (added private key and certificate for https)
kubectl apply -f - << EOF
apiVersion: v1
kind: ConfigMap
metadata:
  name: kbs-config
  namespace: trustee-operator-system
data:
  kbs-config.toml: |
    [http_server]
    sockets = ["0.0.0.0:8080"]
    insecure_http = true
    private_key = "/etc/https-key/https.key"
    certificate = "/etc/https-cert/https.crt"

    [admin]
    insecure_api = true
    auth_public_key = "/etc/auth-secret/kbs.pem"

    [attestation_token]
    insecure_key = true

    [attestation_service]
    type = "coco_as_builtin"
    work_dir = "/opt/confidential-containers/attestation-service"
    policy_engine = "opa"

      [attestation_service.attestation_token_broker]
      type = "Ear"
      policy_dir = "/opt/confidential-containers/attestation-service/policies"
      
      [attestation_service.attestation_token_config]
      duration_min = 5

      [attestation_service.rvps_config]
      type = "BuiltIn"
      
        [attestation_service.rvps_config.storage]
        type = "LocalJson"
        file_path = "/opt/confidential-containers/rvps/reference-values/reference-values.json"

    [[plugins]]
    name = "resource"
    type = "LocalFs"
    dir_path = "/opt/confidential-containers/kbs/repository"

    [policy_engine]
    policy_path = "/opt/confidential-containers/opa/policy.rego"
EOF

kubectl -n trustee-operator-system get deployment trustee-deployment -o yaml | grep image:
# Expected: image: ...v0.13.0


# Ingress Setup
## Ingress Controller
kubectl apply -f https://raw.githubusercontent.com/kubernetes/ingress-nginx/main/deploy/static/provider/kind/deploy.yaml

# Add metallb for LoadBalancer service type
kubectl edit configmap -n kube-system kube-proxy

kubectl get configmap kube-proxy -n kube-system -o yaml | \
sed -e "s/strictARP: false/strictARP: true/" | \
kubectl apply -f - -n kube-system
kubectl apply -f https://raw.githubusercontent.com/metallb/metallb/v0.15.2/config/manifests/metallb-native.yaml

# metallb-one-ip.yaml for loadbalancer with one shared ip: kbs, policy-agent
kubectl apply -f - << EOF
apiVersion: metallb.io/v1beta1
kind: IPAddressPool
metadata:
  name: kbs-one-ip
  namespace: metallb-system
spec:
  addresses:
    - <SET ADRESS>
---
apiVersion: metallb.io/v1beta1
kind: L2Advertisement
metadata:
  name: kbs-adv
  namespace: metallb-system
spec:
  ipAddressPools:
    - kbs-one-ip
EOF

kubectl patch svc kbs-service -n trustee-operator-system \
  -p '{"spec":{"type":"LoadBalancer","loadBalancerIP":"<IP>"}}'

kubectl get svc -n trustee-operator-system kbs-service -w
# Expected: EXTERNAL-IP: <IP>
