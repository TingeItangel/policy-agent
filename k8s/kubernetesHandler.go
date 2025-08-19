package k8s

import (
	"context"
	"fmt"
	"path/filepath"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

var clientset *kubernetes.Clientset // shared client for the whole package

// Init initializes the Kubernetes client once
func Init() error {
	// TODO: Change Path that it can be configured with kubernetes deplyoment file.
	// BUG hardcoded path for testing
	kubeconfig := filepath.Join(
		"/home/mega/.kube", // change if needed
		"config",
	)

	config, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
	if err != nil {
		return err
	}

	clientset, err = kubernetes.NewForConfig(config)
	if err != nil {
		return err
	}

	return nil
}

// GetPod retrieves a Pod object from a given namespace
func GetPod(namespace, podName string) (*corev1.Pod, error) {
	pod, err := clientset.CoreV1().Pods(namespace).Get(context.TODO(), podName, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to get pod %s in namespace %s: %v", podName, namespace, err)
	}
	return pod, nil
}
