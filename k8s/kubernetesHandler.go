package k8s

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"policy-agent/types"
	"strings"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/tools/remotecommand"
)

type Clients struct {
	Local      *kubernetes.Clientset // local cluster (policy-agent, trustee are deployed here)
	LocalCfg   *rest.Config
	Remote     *kubernetes.Clientset   // remote cluster (CoCos are deployed here)
	RemoteCfg  *rest.Config
}

const initDataAnnotationKey = "io.katacontainers.config.runtime.cc_init_data"

type ClientSource int

const (
	SourceInCluster ClientSource = iota
	SourceKubeconfig
	SourceDirect // Host + BearerToken + CAData
)

type directOpts struct {
	Host        string
	BearerToken string
	CAData      []byte
	Insecure    bool
}



// ---------- Public Functions ----------

/**
* InitClients initializes Kubernetes clients for local and remote clusters based on environment variables.
 */
func InitClients() (*Clients, error) {
	local, localCfg, err := newLocalClient()
	if err != nil {
		return nil, fmt.Errorf("local client: %w", err)
	}
	remote, remoteCfg, err := newRemoteClient(local)
	if err != nil {
		return nil, fmt.Errorf("remote client: %w", err)
	}
	// Return both clients
	return &Clients{
		Local:      local,
		LocalCfg:   localCfg,
		Remote:     remote,
		RemoteCfg:  remoteCfg,
	}, nil

}

/**
* Check if ServiceAccount exists in the given namespace for the provided client.
* ServiceAccount are needed for the policy-agent to interact with the clusters.
* local cluster: to manage trustee ConfigMaps and Secrets and reference values
* remote cluster: to patch deployments with updated annotations
* Returns an error if the ServiceAccount does not exist or if the check fails.
*/
func CheckServiceAccountExists(clients *Clients) (error) {
	// NOTE: Names of ServiceAccounts are expected to be "policy-agent-sa" but can be configured via ENV
	localServiceAccountName := os.Getenv("LOCAL_SERVICEACCOUNT_NAME")
	if localServiceAccountName == "" {
		localServiceAccountName = "policy-agent-sa"
	}
	localNamespace := os.Getenv("LOCAL_SERVICEACCOUNT_NAMESPACE")
	if localNamespace == "" {
		localNamespace = "policy-agent"
	}
	remoteServiceAccountName := os.Getenv("REMOTE_SERVICEACCOUNT_NAME")
	if remoteServiceAccountName == "" {
		remoteServiceAccountName = "policy-agent-sa"
	}
	remoteNamespace := os.Getenv("REMOTE_SERVICEACCOUNT_NAMESPACE")
	if remoteNamespace == "" {
		remoteNamespace = "default"
	}

	saLocal := clients.Local.CoreV1().ServiceAccounts(localNamespace)
	_, err := saLocal.Get(context.Background(), localServiceAccountName, v1.GetOptions{})
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			return fmt.Errorf("local service account %s/%s not found", localNamespace, localServiceAccountName)
		}
		return fmt.Errorf("failed to get local service account %s/%s: %w", localNamespace, localServiceAccountName, err)
	}

	saRemote := clients.Remote.CoreV1().ServiceAccounts(remoteNamespace)
	_, err = saRemote.Get(context.Background(), remoteServiceAccountName, v1.GetOptions{})
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			return fmt.Errorf("remote service account %s/%s not found", remoteNamespace, remoteServiceAccountName)
		}
		return fmt.Errorf("failed to get remote service account %s/%s: %w", remoteNamespace, remoteServiceAccountName, err)
	}
	return nil
}

/**
* Extract the base64-encoded initData from the annotation of a runtime object (only Deployment).
* Returns an error if the annotation is not found or if the object is not a Deployment.
 */
func GetInitDataFromAnnotation(runtimeObj runtime.Object) (string, error) {
	deployment, ok := runtimeObj.(*appsv1.Deployment)
	if !ok {
		return "", fmt.Errorf("expected Deployment object, got %T", runtimeObj)
	}
	var annotations map[string]string

	annotations = deployment.Spec.Template.Annotations
	if annotations == nil { // fallback: deployment-level annotations
		annotations = deployment.Annotations
	}
	if annotations == nil {
		return "", fmt.Errorf("no annotations found on object")
	}

	base64InitData, ok := annotations[initDataAnnotationKey]
	if !ok {
		return "", fmt.Errorf("annotation %q not found", initDataAnnotationKey)
	}

	return base64InitData, nil
}

/**
* Update the annotation value of a runtime object (only Deployment) in the provided client and namespace
* with the annotationValue. Returns an error if the update fails.
 */
func UpdateAnnotationValue(client *kubernetes.Clientset, runtimeObj runtime.Object, annotationValue, namespace string) error {
	switch obj := runtimeObj.(type) {

	case *corev1.Pod:
		return fmt.Errorf(
			"only Deployments are supported for automatic updates; standalone Pod '%s' in namespace '%s' cannot be updated automatically",
			obj.Name, namespace,
		)

	case *appsv1.Deployment:
		if obj.Spec.Template.Annotations == nil {
			obj.Spec.Template.Annotations = map[string]string{}
		}
		obj.Spec.Template.Annotations[initDataAnnotationKey] = annotationValue

		_, err := client.AppsV1().Deployments(namespace).Update(context.TODO(), obj, v1.UpdateOptions{})
		if err != nil {
			return fmt.Errorf("failed to update deployment annotation: %w", err)
		}
		return nil

	default:
		return fmt.Errorf("unsupported runtime object type: %T", obj)
	}
}

/**
* Get Deployment from cluster based on client and PolicyRequest
 */
func GetDeploymentFromCluster(client *kubernetes.Clientset,req types.PolicyRequest) (*appsv1.Deployment, error) {
	deployments := client.AppsV1().Deployments(req.Body.Namespace)
	if deployments == nil {
		return nil, fmt.Errorf("failed to get deployments client for namespace %s", req.Body.Namespace)
	}

	// Check if the specified deployment exists
	deployment, err := deployments.Get(context.Background(), req.Body.DeploymentName, v1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to get deployment %s/%s: %w", req.Body.Namespace, req.Body.DeploymentName, err)
	}

	return deployment, nil
}



/**
* WaitForDeploymentRollout waits until the deployment has fully rolled out or the timeout is reached.
*/
func WaitForDeploymentRollout(
    ctx context.Context,
    client kubernetes.Interface,
    namespace, deploymentName string,
    timeout time.Duration,
) error {
    ctx, cancel := context.WithTimeout(ctx, timeout)
    defer cancel()

    ticker := time.NewTicker(2 * time.Second)
    defer ticker.Stop()

    // remember target generation
    dep, err := client.AppsV1().Deployments(namespace).Get(ctx, deploymentName, metav1.GetOptions{})
    if err != nil {
        return fmt.Errorf("get deployment: %w", err)
    }
    targetGeneration := dep.Generation
    var desired int32 = 1
    if dep.Spec.Replicas != nil {
        desired = *dep.Spec.Replicas
    }

    for {
        select {
        case <-ctx.Done():
            return fmt.Errorf("timeout waiting for deployment %s/%s rollout: %w", namespace, deploymentName, ctx.Err())
        case <-ticker.C:
            dep, err := client.AppsV1().Deployments(namespace).Get(ctx, deploymentName, metav1.GetOptions{})
            if err != nil {
                return fmt.Errorf("get deployment: %w", err)
            }

			// check if observed generation matches target generation
            if dep.Status.ObservedGeneration < targetGeneration {
                continue
            }

            if dep.Status.UpdatedReplicas < desired {
                continue
            }
            if dep.Status.ReadyReplicas < desired {
                continue
            }
            if dep.Status.AvailableReplicas < desired {
                continue
            }
            if dep.Status.UnavailableReplicas > 0 {
                continue
            }

            return nil
        }
    }
}



/**
* Get new config_mr value from the remote cluster for the given deployment and namespace
* The deployment must be running in the remote cluster and have the following command as allowed command in the kata-policy:
* kubectl exec -n <namespace> <pod> -- \
  sh -c "curl -s http://127.0.0.1:8006/aa/token?token_type=kbs \
    | jq -r '.token' \
    | cut -d '.' -f2 \
    | base64 -d \
    | jq -r '.submods.cpu.\"ear.veraison.annotated-evidence\".tdx.quote.body.mr_config_id'"
* This command retrieves the current mr_config_id from the KBS token inside the CoCo pod.
*
* Returns the mr_config_id as string or an error if the retrieval fails.
 */
func GetNewMrConfigId(clients *Clients , deploymentName, namespace string) (string, error) {
	ctx := context.Background()

	pods, err := clients.Remote.CoreV1().Pods(namespace).List(ctx, v1.ListOptions{
		LabelSelector: fmt.Sprintf("app=%s", deploymentName),
	})
	if err != nil || len(pods.Items) == 0 {
		return "", fmt.Errorf("failed to list pods for deployment %s: %w", deploymentName, err)
	}

	pod := pods.Items[0].Name

	// Get Token command
	// NOTE: This command must be allowed in the kata-policy of the CoCo deployment in the remote cluster to get new mr_config_id value
	cmd := []string{
		"curl", "-s", "http://127.0.0.1:8006/aa/token?token_type=kbs",
	}

	// Exec into pod
	req := clients.Remote.CoreV1().RESTClient().
		Post().
		Namespace(namespace).
		Resource("pods").
		Name(pod).
		SubResource("exec").
		VersionedParams(&corev1.PodExecOptions{
			Container: pods.Items[0].Spec.Containers[0].Name,
			Command:   cmd,
			Stdout:    true,
			Stderr:    true,
		}, scheme.ParameterCodec)

	exec, err := remotecommand.NewSPDYExecutor(clients.RemoteCfg, "POST", req.URL())
	if err != nil {
		return "", fmt.Errorf("exec init: %w", err)
	}

	// --- Execute the command ---
	var stdout, stderr bytes.Buffer
	err = exec.StreamWithContext(ctx, remotecommand.StreamOptions{
		Stdout: &stdout,
		Stderr: &stderr,
	})

	// FIXME: DEBUG PRINT OUTPUT
	
	log.Printf("Exec stdout: %s", stdout.String())
	log.Printf("Exec stderr: %s", stderr.String())

	if err != nil {
		return "", fmt.Errorf("exec error: %v, stderr=%s", err, stderr.String())
	}


	raw := strings.TrimSpace(stdout.String())
	var resp struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal([]byte(raw), &resp); err != nil {
		return "", fmt.Errorf("failed to parse KBS response JSON: %w", err)
	}
	if resp.Token == "" {
		return "", fmt.Errorf("no token field in KBS response")
	}
	// Decode JWT token to get mr_config_id
	parts := strings.Split(resp.Token, ".")
	if len(parts) < 2 {
		return "", fmt.Errorf("invalid JWT format")
	}
	payloadB64 := parts[1]

	// NOTE: JWT base64url encoding may omit padding, but Go's base64 decoder requires it
	if l := len(payloadB64) % 4; l != 0 {
		payloadB64 += strings.Repeat("=", 4-l)
	}
	payloadJSON, err := base64.URLEncoding.DecodeString(payloadB64)

	if err != nil {
		return "", fmt.Errorf("failed to decode JWT payload: %w", err)
	}

	var payload struct {
		Submods struct {
			CPU struct {
				EarVeraisonAnnotatedEvidence struct {
					TDX struct {
						Quote struct {
							Body struct {
								MrConfigID string `json:"mr_config_id"`
							} `json:"body"`
						} `json:"quote"`
					} `json:"tdx"`
				} `json:"ear.veraison.annotated-evidence"`
			} `json:"cpu"`
		} `json:"submods"`
	}
	if err := json.Unmarshal(payloadJSON, &payload); err != nil {
		return "", fmt.Errorf("failed to parse JWT payload JSON: %w", err)
	}

	mr := strings.TrimSpace(payload.Submods.CPU.
	EarVeraisonAnnotatedEvidence.TDX.
	Quote.Body.MrConfigID)
		
	if mr == "" {
		return "", fmt.Errorf("mr_config_id empty")
	}

	return mr, nil
}



// ---------- Internal Functions ----------


/**
* Create Kubernetes client for local cluster
* It first tries in-cluster config, then falls back to kubeconfig file.
* Returns the clientset and rest.Config or an error if creation fails.
 */
func newLocalClient() (*kubernetes.Clientset, *rest.Config, error) {
	// inCluster when running inside a cluster
	if cfg, err := rest.InClusterConfig(); err == nil {
		tune(cfg)
		cs, err := kubernetes.NewForConfig(cfg)
		if err != nil { return nil, nil, err }
		return cs, cfg, nil
	}

	// Fallback: Kubeconfig (only when running outside cluster, e.g. local dev)
	kc := kubeconfigPath()
	over := &clientcmd.ConfigOverrides{}
	// if KUBECONTEXT_LOCAL is set, use it as current context
	if ctx := os.Getenv("KUBECONTEXT_LOCAL"); ctx != "" {
		over.CurrentContext = ctx
	}
	loading := &clientcmd.ClientConfigLoadingRules{ExplicitPath: kc}
	cfg, err := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(loading, over).ClientConfig()
	if err != nil { return nil, nil, err }
	tune(cfg) // apply defaults
	cs, err := kubernetes.NewForConfig(cfg)
	if err != nil { return nil, nil, err }
	return cs, cfg, nil
}

/**
* Create Kubernetes client for remote cluster
 */
func newRemoteClient(_ *kubernetes.Clientset) (*kubernetes.Clientset, *rest.Config, error) {
	remoteAPIServerURL  := os.Getenv("REMOTE_API_SERVER_URL")
	remoteTokenFile  := os.Getenv("REMOTE_TOKEN_FILE")
	remoteCAFile  := os.Getenv("REMOTE_CA_FILE")

	if remoteAPIServerURL  == "" || remoteTokenFile  == "" {
		return nil, nil, fmt.Errorf("REMOTE_API_SERVER_URL or REMOTE_TOKEN_FILE not set")
	}

	token, err := os.ReadFile(remoteTokenFile)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read remote token file %s: %w", remoteTokenFile , err)
	}

	var ca []byte
	if remoteCAFile  != "" {
		ca, err = os.ReadFile(remoteCAFile)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to read remote CA file %s: %w", remoteCAFile , err)
		}
	}

	client, cfg, err := newDirectClient(directOpts{
			Host:        remoteAPIServerURL,
			BearerToken: strings.TrimSpace(string(token)),
			CAData:      ca,
			Insecure:    false,
		})
	
	if err == nil {
		return client, cfg, nil
	}
	return nil, nil, fmt.Errorf("failed to create remote client: no valid credentials found")
}


func newDirectClient(options directOpts) (*kubernetes.Clientset, *rest.Config, error) {
	if options.Host == "" || options.BearerToken == "" {
		return nil, nil, fmt.Errorf("direct client needs Host and BearerToken")
	}
	tls := rest.TLSClientConfig{Insecure: options.Insecure}
	
	if len(options.CAData) > 0 {
		tls.CAData = options.CAData
	}
	cfg := &rest.Config{
		Host:            options.Host,
		BearerToken:     options.BearerToken,
		TLSClientConfig: tls,
	}
	tune(cfg)
	client, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return nil, nil, err
	}
	return client, cfg, err
}

/**
* apply some default tuning to rest.Config
*/
func tune(cfg *rest.Config) {
	cfg.Timeout = 15 * time.Second
	cfg.QPS = 20
	cfg.Burst = 40
}

/**
* get kubeconfig path from KUBECONFIG env or default location 
*/
func kubeconfigPath() string {
	if path := os.Getenv("KUBECONFIG"); path != "" {
		return path
	}
	home, _ := os.UserHomeDir()
	return home + string(os.PathSeparator) + ".kube" + string(os.PathSeparator) + "config"
}


/**
* Check if a Deployment has fully rolled out
 */
func isDeploymentRolledOut(dep *appsv1.Deployment) bool {
    // No replicas defined means there is nothing to roll out
    if dep.Spec.Replicas == nil {
        return true
    }

    desired := *dep.Spec.Replicas

    if dep.Status.UpdatedReplicas < desired {
        return false
    }
    if dep.Status.ReadyReplicas < desired {
        return false
    }
    if dep.Status.AvailableReplicas < desired {
        return false
    }

    return true
}


// ---------- Test Functions ----------


/**
* Ping the Kubernetes API server to verify connectivity
 */
func PingAPI(ctx context.Context, clients *Clients) error {
	// Ping local cluster
	ver, err := clients.Local.ServerVersion()
	if err != nil { return fmt.Errorf("api not reachable: %w", err) }
	fmt.Printf("Connected, version: %s\n", ver.GitVersion)

	// Ping remote cluster
	ver, err = clients.Remote.ServerVersion()
	if err != nil { return fmt.Errorf("remote api not reachable: %w", err) }
	fmt.Printf("Connected to remote, version: %s\n", ver.GitVersion)

	// ##########################################
	// DEBUG Ping remote cluster to verify connectivity
	// ##########################################

	// deployments, err := clients.Local.AppsV1().Deployments("default").List(ctx, v1.ListOptions{})
	// if err != nil { return fmt.Errorf("list deployments default: %w", err) }
	// fmt.Printf("Found %d deployments in default\n", len(deployments.Items))
	
	// log.Printf("InitClients final: remoteTokenLen=%d remoteHost=%s",
	// 	len(clients.RemoteCfg.BearerToken),
	// 	clients.RemoteCfg.Host,
	// )

	// pods, err := clients.Remote.CoreV1().Pods("default").List(ctx, v1.ListOptions{})
	// if err != nil { return fmt.Errorf("list pods default: %w", err) }
	// fmt.Printf("Found %d pods in default\n", len(pods.Items))

	// END DEBUG Ping remote cluster to verify connectivity
	
	return nil
}