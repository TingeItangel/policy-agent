package k8s

import (
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"policy-agent/types"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

var (
	TrustedClient   *kubernetes.Clientset
	UntrustedClient *kubernetes.Clientset
)

const initDataAnnotationKey = "io.katacontainers.config.runtime.cc_init_data"

/**
* Init connection to the trusted Kubernetes client via in-cluster config or kubeconfig (for local dev)
 */
func InitTrusted() error {
	config, err := rest.InClusterConfig()
	if err != nil {
		// Fallback to kubeconfig (for local dev)
		// TODO: Use KUBECONFIG env var of deplyoment
		kubeconfig := filepath.Join(homeDir(), ".kube", "kind-trusted-config")
		config, err = clientcmd.BuildConfigFromFlags("", kubeconfig)
		if err != nil {
			return fmt.Errorf("failed to build trusted kubeconfig: %w", err)
		}
	}

	TrustedClient, err = kubernetes.NewForConfig(config)
	if err != nil {
		return fmt.Errorf("failed to create trusted clientset: %w", err)
	}
	return nil
}

/**
* Init connection to untrusted the Kubernetes client via Service Account token and CA cert
 */
func InitUntrusted(apiServerURL string) error {
	// TODO: Get values from trustee as secrets
	// Read the token
	token := "ZXlKaGJHY2lPaUpTVXpJMU5pSXNJbXRwWkNJNklqRTNNV0pIUkdabU9Hb3dOQzFmV0MxbmRGUXhaMTlMTFVaUFZrWkJZelZ6TmxCRldXcHZVRUpCUVhNaWZRLmV5SnBjM01pT2lKcmRXSmxjbTVsZEdWekwzTmxjblpwWTJWaFkyTnZkVzUwSWl3aWEzVmlaWEp1WlhSbGN5NXBieTl6WlhKMmFXTmxZV05qYjNWdWRDOXVZVzFsYzNCaFkyVWlPaUpqYjI1bWFXUmxiblJwWVd3aUxDSnJkV0psY201bGRHVnpMbWx2TDNObGNuWnBZMlZoWTJOdmRXNTBMM05sWTNKbGRDNXVZVzFsSWpvaWNHOXNhV041TFdGblpXNTBMWFJ2YTJWdUlpd2lhM1ZpWlhKdVpYUmxjeTVwYnk5elpYSjJhV05sWVdOamIzVnVkQzl6WlhKMmFXTmxMV0ZqWTI5MWJuUXVibUZ0WlNJNkluQnZiR2xqZVMxaFoyVnVkQ0lzSW10MVltVnlibVYwWlhNdWFXOHZjMlZ5ZG1salpXRmpZMjkxYm5RdmMyVnlkbWxqWlMxaFkyTnZkVzUwTG5WcFpDSTZJalprTjJOaVpEVTFMV1l6TnpndE5HRXdPUzFoTUdJMkxXTXlPR1ZrWTJFd01XVXlZeUlzSW5OMVlpSTZJbk41YzNSbGJUcHpaWEoyYVdObFlXTmpiM1Z1ZERwamIyNW1hV1JsYm5ScFlXdzZjRzlzYVdONUxXRm5aVzUwSW4wLkpzck5nVjMxRDRFN3dZMGpTS2VKRW52ZXNnR1lUcDNFZUhib0RxUm91VHkyVV9jdEtGOUpTM3ppVHJVMTNLZWlXVF9QT3d3YmZBbVI4WUJOYWhSd1JMcEpLbE9XMUVHbWFDXzVtQkNJT3pkX0V1bTdvMmp4UXNZeVVzNU0tMF8ySWd1d2NKMGRsWFNlRlFrcVQ3c01CenlBRUhzNjNnQlZ2ZkE0enA3c2hMMzJMbC1qTkU5VUV5Ym4tQ1lMekRyeEJ1OE1DUExncFVVam9tdGpvR1R6QXZnWFh1a19qaEw3MEMzVkhKQWRuanFRMFJ5Q1Y3eEVHQXY3dkNwRFdaWXZaODdFdmRqOFVScGRiaTVSQzRDYzNLWWRWeU54Y3RvYVlSYnE0LW5wQUFVWlBjc3J1d3ZPNFY5UmgyeFlQeTAzdUtHYllJV2owX04yVUlGdG1kSnN6QQ=="

	// Read the CA cert
	caBase64 := "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSURCVENDQWUyZ0F3SUJBZ0lJTG83Q21yWFQ1Qjh3RFFZSktvWklodmNOQVFFTEJRQXdGVEVUTUJFR0ExVUUKQXhNS2EzVmlaWEp1WlhSbGN6QWVGdzB5TlRBNE16QXdOekl3TkRsYUZ3MHpOVEE0TWpnd056STFORGxhTUJVeApFekFSQmdOVkJBTVRDbXQxWW1WeWJtVjBaWE13Z2dFaU1BMEdDU3FHU0liM0RRRUJBUVVBQTRJQkR3QXdnZ0VLCkFvSUJBUUN5S3lwd1hNWm9QSzFaSXdHMllSQzdFbkhFMXpoc3p5bTRPa0xyTi9ZOVZBR1BqaVFUWWUxNWd5cUEKOWNVc1QwemRNcUV5UHJmek9MQS9TaVBXM2JpNHpWMjdTNy9oZ09CaU84bDljbUYzK0RaRnBYWkREbEs0bXlTUwppVC84cXdnM2NzUUY3WlhTd0NObmJIeS9mYnh5WE5tay9ndVhjdUdHZVc0SE9DVEp3TGFlM3QwaHROcDA3L3cvCjdBK1R3M1MvOWZJdXJqY1ZmbUxrUjhrSmNYeE5uMmlwbzdKN0JPMWxxS0RieG9WMGlBbE5iWHp6dS81RTN0dS8KdU8vT3pZZVZVUjNoUmNTQVZ0RUZ2UWNJL2JQaDRCS3lKMDBLYnh1MDNmQzFJRTYveElVTWhJb1FwVE1JdExzMwo5VElxQk4vUWRFN1RncDFaWjZsemdPLzN2LzNuQWdNQkFBR2pXVEJYTUE0R0ExVWREd0VCL3dRRUF3SUNwREFQCkJnTlZIUk1CQWY4RUJUQURBUUgvTUIwR0ExVWREZ1FXQkJRTWgzaldKRm5PeVB5VXVkeDA3ekhVOURLNEdEQVYKQmdOVkhSRUVEakFNZ2dwcmRXSmxjbTVsZEdWek1BMEdDU3FHU0liM0RRRUJDd1VBQTRJQkFRQnBsZlZsU08zWgpSUjVQSlF0RGsxcndsNkcydDBNMTBrMHZBTWRkbERFMHNJK0dDZ2U1SThoK1RoblFLSDI4VUJqUFlMRkNjVHNhCnpjNGQzUFFhN0drenJpRFBqc1NOZXVmaDFiMWMwb01jM0o1dHFzY3FUaTZBN241NjJrVHZEL3FZdWlZUThFTmwKYmNSaDkydFgxTXpMSTVyZ0Fkclc4VVdUb3R3dExaT3o4WnJZa3ZBMzZlcEZPMURYS0tLMy9mZDRXV2VSWXFxeApQRGdzOFlGaERBbjJjNU5DMHBtY1BYdXY2L0R4bzhuRjl5dWpPM1NhUVRBRmdjT3o4cWF0ZEc0bjNvMUt2d2VnCjZKcTcvWk9JbHFZRkQ5aS9tYzZhbzJpNi9INDBYK0wwZmZIR0tKdjZOeHMreU8vanlGZUd1Y1AvVUg2cnhESy8KRDNBbnRXQnRIVEx1Ci0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0K"

	tokenPlain, err := base64.StdEncoding.DecodeString(token)
	if err == nil {
		token = string(tokenPlain)
	}

	caData, err := base64.StdEncoding.DecodeString(caBase64)
	if err != nil {
		return fmt.Errorf("failed to decode CA cert: %w", err)
	}

	// Build rest.Config manually
	config := &rest.Config{
		Host:        apiServerURL,
		BearerToken: token,
		TLSClientConfig: rest.TLSClientConfig{
			CAData: caData,
		},
	}

	UntrustedClient, err = kubernetes.NewForConfig(config)
	if err != nil {
		return fmt.Errorf("failed to create untrusted clientset: %w", err)
	}
	return nil
}

/**
* Extract the base64-encoded initData from the annotation of a runtime object (only Deployment).
* Returns an error if the annotation is not found or if the object is not a Deployment.
 */
func GetInitDataFromAnnotaion(runtimeObj runtime.Object) (string, error) {
	deployment, ok := runtimeObj.(*appsv1.Deployment)
	if !ok {
		return "", fmt.Errorf("expected Deployment object, got %T", runtimeObj)
	}
	// const initDataAnnotationKey = "io.katacontainers.config.runtime.cc_init_data"
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
* Update the annotation value of a runtime object (only Deployment) in untrusted cluster
* with the provided base64-encoded initData.
 */
func UpdateAnnotationValue(runtimeObj runtime.Object, annotationValue, namespace string) error {
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

		_, err := UntrustedClient.AppsV1().Deployments(namespace).Update(context.TODO(), obj, metav1.UpdateOptions{})
		if err != nil {
			return fmt.Errorf("failed to update deployment annotation: %w", err)
		}
		return nil

	default:
		return fmt.Errorf("unsupported runtime object type: %T", obj)
	}
}

/**
* Get Deployment from untrusted cluster based on PolicyRequestBody
 */
func GetDeploymentFromUntrustedCluster(req types.PolicyRequestBody) (*appsv1.Deployment, error) {
	if UntrustedClient == nil {
		return nil, fmt.Errorf("untrusted client not initialized")
	}

	deployments := UntrustedClient.AppsV1().Deployments(req.Namespace)

	// BUG: Log all deployments in the namespace for debugging
	deployList, err := deployments.List(context.Background(), metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to list deployments: %w", err)
	}
	fmt.Printf("Deployments in namespace %s:\n", req.Namespace)
	for _, d := range deployList.Items {
		fmt.Printf("- %s\n", d.Name)
	}

	// Check if the specified deployment exists
	deployment, err := deployments.Get(context.Background(), req.DeploymentName, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to get deployment %s/%s: %w", req.Namespace, req.DeploymentName, err)
	}

	return deployment, nil
}

func homeDir() string {
	if h := os.Getenv("HOME"); h != "" {
		return h
	}
	return os.Getenv("USERPROFILE") // windows
}
