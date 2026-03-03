# https://github.com/canonical/tdx?tab=readme-ov-file#setup-host-os
git clone -b main https://github.com/canonical/tdx.git
cd tdx/
sudo ./setup-tdx-host.sh
sudo reboot

# verify tdx
sudo dmesg | grep tdx

# Install QGS
echo 'deb [signed-by=/etc/apt/keyrings/intel-sgx-keyring.asc arch=amd64] https://download.01.org/intel-sgx/sgx_repo/ubuntu noble main' | sudo tee /etc/apt/sources.list.d/intel-sgx.list
wget https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key
sudo mkdir -p /etc/apt/keyrings
cat intel-sgx-deb.key | sudo tee /etc/apt/keyrings/intel-sgx-keyring.asc > /dev/null
sudo apt-get update

# Install QGS
sudo apt install -y \
    tdx-qgs \
    libsgx-dcap-default-qpl \
    libsgx-dcap-ql
# more details: https://download.01.org/intel-sgx/latest/dcap-latest/linux/docs/Intel_SGX_SW_Installation_Guide_for_Linux.pdf

# Check QGS
sudo journalctl -u qgsd -f

# Configure QCNL
# On start, the QGS reads the configuration file `/etc/sgx_default_qcnl.conf`, and uses the contained settings for TD Quote Generation. This file contains various settings that might be important in your environment.
# PCCS (https://cc-enabling.trustedservices.intel.com/intel-tdx-enabling-guide/02/infrastructure_setup/#collateral-caching-service)

vim /etc/sgx_default_qcnl.conf
# Set the PCCS URL to your PCCS instance
# Set insecure http to to allow self-signed certificates

# After changing settings in the file /etc/sgx_default_qcnl.conf, you have to restart the QGS:
sudo systemctl restart qgsd.service

# Test if QGS is working
sudo journalctl -u qgsd -f

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


### Setup Cluster ###

sudo kubeadm init --pod-network-cidr=10.244.0.0/16

mkdir -p $HOME/.kube
sudo cp -i /etc/kubernetes/admin.conf $HOME/.kube/config
sudo chown $(id -u):$(id -g) $HOME/.kube/config

# Switch to this cluster
export KUBECONFIG=$HOME/.kube/config

# Check if cluster is up and running
kubectl get pods --all-namespaces

# Container Network Interface: Without a CNI plugin, pods cannot reach each other - not even on the same node. 
kubectl apply -f https://github.com/flannel-io/flannel/releases/latest/download/kube-flannel.yml

# Needed to schedule other pods on the single node https://kubernetes.io/docs/setup/production-environment/tools/kubeadm/create-cluster-kubeadm/#control-plane-node-isolation
kubectl taint nodes --all node-role.kubernetes.io/control-plane-
# Needed for running cocos https://confidentialcontainers.org/docs/getting-started/prerequisites/software/
kubectl label node serveraica01 node.kubernetes.io/worker=

# Install Confidential Containers Operator
kubectl apply -k "github.com/confidential-containers/operator/config/release?ref=v0.16.0"
kubectl apply -k "github.com/confidential-containers/operator/config/samples/ccruntime/default?ref=v0.16.0"
kubectl get pods -n confidential-containers-system --watch

# verify cluster setup and cocos runtime classes
kubectl get nodes
kubectl get pods -A
kubectl get runtimeclass


### Create Service Account in untrusted cluster to access trusted cluster ###
export KUBECONFIG=/$HOME/.kube/config  # make sure we’re using the untrusted cluster

kubectl create namespace confidential
kubectl create serviceaccount policy-agent -n confidential

# policy-agent-role.yaml
kubectl apply -f - <<EOF
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: policy-agent-role
rules:
  - apiGroups: [""] # core API group
    resources: ["pods", "services", "secrets"]
    verbs: ["get", "list", "watch", "create", "update", "patch", "delete"]
  - apiGroups: ["apps"] # deployments, daemonsets, etc.
    resources: ["deployments", "daemonsets", "statefulsets", "replicasets"]
    verbs: ["get", "list", "watch", "create", "update", "patch", "delete"]
EOF

# Bind Role to Service Account
kubectl apply -f - <<EOF
# policy-agent-rolebinding.yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: policy-agent-binding
subjects:
- kind: ServiceAccount
  name: policy-agent
  namespace: confidential
roleRef:
  kind: ClusterRole
  name: policy-agent-role
  apiGroup: rbac.authorization.k8s.io
EOF

# Create Secret for acc
kubectl apply -f - << EOF
apiVersion: v1
kind: Secret
metadata:
  name: policy-agent-token
  namespace: confidential
  annotations:
    kubernetes.io/service-account.name: "policy-agent"
type: kubernetes.io/service-account-token
EOF

# Extract the ServiceAccount token and CA
export TOKEN=$(kubectl get secret policy-agent-token -n confidential -o jsonpath="{.data.token}")
export CA=$(kubectl get secret policy-agent-token -n confidential -o jsonpath="{.data['ca\.crt']}")

# Set Token and CA in deplyoment of poilcy-agent in trusted cluster
