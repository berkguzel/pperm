package kubernetes

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/berkguzel/pperm/pkg/analyzer"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

type Client struct {
	clientset *kubernetes.Clientset
}

func NewClient(kubeconfigPath string) (*Client, error) {
	var config *rest.Config
	var err error

	// If running inside cluster
	if os.Getenv("KUBERNETES_SERVICE_HOST") != "" {
		config, err = rest.InClusterConfig()
	} else {
		// Get kubeconfig path
		if kubeconfigPath == "" {
			if envPath := os.Getenv("KUBECONFIG"); envPath != "" {
				kubeconfigPath = envPath
			} else {
				homeDir, _ := os.UserHomeDir()
				kubeconfigPath = filepath.Join(homeDir, ".kube", "config")
			}
		}

		// Use the kubeconfig file
		config, err = clientcmd.BuildConfigFromFlags("", kubeconfigPath)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to create config: %v", err)
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create clientset: %v", err)
	}

	return &Client{clientset: clientset}, nil
}

func (c *Client) GetPod(ctx context.Context, name, namespace string) (analyzer.Pod, error) {
	// This makes API call to: GET /api/v1/namespaces/{namespace}/pods/{name}
	pod, err := c.clientset.CoreV1().Pods(namespace).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return analyzer.Pod{}, err
	}

	return analyzer.Pod{
		Spec: analyzer.PodSpec{
			ServiceAccountName: pod.Spec.ServiceAccountName,
		},
	}, nil
}

func (c *Client) GetServiceAccountIAMRole(ctx context.Context, namespace, saName string) (string, error) {
	// This makes API call to: GET /api/v1/namespaces/{namespace}/serviceaccounts/{name}
	sa, err := c.clientset.CoreV1().ServiceAccounts(namespace).Get(ctx, saName, metav1.GetOptions{})
	if err != nil {
		return "", err
	}

	// Look for the IAM role annotation
	roleARN, exists := sa.Annotations["eks.amazonaws.com/role-arn"]
	if !exists {
		return "", fmt.Errorf("no IAM role annotation found on service account")
	}

	return roleARN, nil
}
