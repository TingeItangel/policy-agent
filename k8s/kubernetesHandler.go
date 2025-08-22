package k8s

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

var clientset *kubernetes.Clientset // shared client for the whole package

// Init initializes the Kubernetes client once
func Init() error {
	config, err := rest.InClusterConfig()
	if err != nil {
		// Fallback to kubeconfig (for local dev)
		kubeconfig := filepath.Join(
			// Adjust if not in default place
			homeDir(), ".kube", "config",
		)
		config, err = clientcmd.BuildConfigFromFlags("", kubeconfig)
		if err != nil {
			return err
		}
	}

	clientset, err = kubernetes.NewForConfig(config)
	if err != nil {
		return err
	}

	return nil
}

func homeDir() string {
	if h := os.Getenv("HOME"); h != "" {
		return h
	}
	return os.Getenv("USERPROFILE") // windows
}

// GetPod retrieves a Pod object from a given namespace
func GetPod(namespace string, podName string) (*corev1.Pod, error) {
	pod, err := clientset.CoreV1().Pods(namespace).Get(
		context.TODO(),
		podName,
		metav1.GetOptions{},
	)
	if err != nil {
		return nil, fmt.Errorf("failed to get pod %s in namespace %s: %v", podName, namespace, err)
	}
	return pod, nil
}

func GetDeplyoment(namespace string, deploymentName string) (*appsv1.Deployment, error) {
	deployment, err := clientset.AppsV1().Deployments(namespace).Get(
		context.TODO(),
		deploymentName,
		metav1.GetOptions{},
	)
	if err != nil {
		return nil, fmt.Errorf("failed to get deployment %s/%s: %w", namespace, deploymentName, err)
	}

	return deployment, nil
}

func GetInitDataFromAnnotaion(runtimeObj runtime.Object, isDepoylemt bool) (string, error) {
	const initDataAnnotation = "io.katacontainers.config.runtime.cc_init_data"
	var annotations map[string]string

	if isDepoylemt {
		deploy, ok := runtimeObj.(*appsv1.Deployment)
		if !ok {
			return "", fmt.Errorf("expected Deployment object, got %T", runtimeObj)
		}
		annotations = deploy.Spec.Template.Annotations
		if annotations == nil { // fallback: deployment-level annotations
			annotations = deploy.Annotations
		}
	} else {
		pod, ok := runtimeObj.(*corev1.Pod)
		if !ok {
			return "", fmt.Errorf("expected Pod object, got %T", runtimeObj)
		}
		annotations = pod.Annotations
	}

	if annotations == nil {
		return "", fmt.Errorf("no annotations found on object")
	}

	base64InitData, ok := annotations[initDataAnnotation]
	if !ok {
		return "", fmt.Errorf("annotation %q not found", initDataAnnotation)
	}

	return base64InitData, nil
}
