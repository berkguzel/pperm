package analyzer

import (
	"context"
	"fmt"

	"github.com/berkguzel/pperm/internal/options"
	"github.com/berkguzel/pperm/pkg/aws"
	"github.com/berkguzel/pperm/pkg/types"
	corev1 "k8s.io/api/core/v1"
)

type K8sClient interface {
	GetPod(ctx context.Context, name, namespace string) (Pod, error)
	GetServiceAccountIAMRole(ctx context.Context, namespace, saName string) (string, error)
}

type AWSClient interface {
	GetRolePolicies(ctx context.Context, roleName string) ([]types.Policy, error)
	GetPolicyPermissions(ctx context.Context, policyArn string) ([]types.PermissionDisplay, error)
}

type Analyzer struct {
	k8sClient K8sClient
	awsClient AWSClient
}

func New(k8sClient K8sClient, awsClient AWSClient) *Analyzer {
	return &Analyzer{
		k8sClient: k8sClient,
		awsClient: awsClient,
	}
}

type Pod struct {
	Spec PodSpec
}

type PodSpec struct {
	ServiceAccountName string
}

func (a *Analyzer) analyzeNamespace(_ context.Context, _ string) ([]types.PodPermissions, error) {
	// TODO: Implement namespace-wide analysis
	// For now, return empty slice
	return []types.PodPermissions{}, nil
}

func (a *Analyzer) analyzePod(ctx context.Context, podName, namespace string, opts *options.Options) ([]types.PodPermissions, error) {
	pod, err := a.k8sClient.GetPod(ctx, podName, namespace)
	if err != nil {
		return nil, fmt.Errorf("failed to get pod %s: %v", podName, err)
	}

	saName := pod.Spec.ServiceAccountName
	if saName == "" {
		saName = "default"
	}

	iamRole, err := a.k8sClient.GetServiceAccountIAMRole(ctx, namespace, saName)
	if err != nil {
		return nil, fmt.Errorf("no IAM role found for service account %s: %v", saName, err)
	}

	policies, err := a.awsClient.GetRolePolicies(ctx, iamRole)
	if err != nil {
		return nil, fmt.Errorf("failed to get policies for role %s: %v", iamRole, err)
	}

	return []types.PodPermissions{{
		PodName:        podName,
		Namespace:      namespace,
		ServiceAccount: saName,
		IAMRole:        iamRole,
		Policies:       policies,
	}}, nil
}

func (a *Analyzer) Analyze(opts *options.Options) ([]types.PodPermissions, error) {
	ctx := context.Background()

	if opts.PodName != "" {
		return a.analyzePod(ctx, opts.PodName, opts.Namespace, opts)
	}

	return a.analyzeNamespace(ctx, opts.Namespace)
}

func AnalyzePodPermissions(pod *corev1.Pod, awsClient *aws.Client) (types.PodPermissions, error) {
	// Get service account name
	saName := pod.Spec.ServiceAccountName
	if saName == "" {
		saName = "default"
	}

	// Get IAM role from service account annotations
	iamRole := pod.Spec.ServiceAccountName // TODO: Get actual IAM role from annotations

	policies, err := awsClient.GetRolePolicies(context.Background(), iamRole)
	if err != nil {
		return types.PodPermissions{}, fmt.Errorf("failed to get role policies: %v", err)
	}

	fmt.Printf("Debug: Analyzer found %d policies with permissions\n", len(policies))
	for _, policy := range policies {
		fmt.Printf("Debug: Policy %s has %d permissions\n", policy.Name, len(policy.Permissions))
	}

	podPerms := types.PodPermissions{
		PodName:        pod.Name,
		Namespace:      pod.Namespace,
		ServiceAccount: saName,
		IAMRole:        iamRole,
		Policies:       policies,
	}

	return podPerms, nil
}
