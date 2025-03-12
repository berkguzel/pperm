package aws

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/iam"
)

type Client struct {
	iamClient *iam.Client
}

func NewClient() (*Client, error) {
	// First try environment variables
	region := os.Getenv("AWS_REGION")
	if region == "" {
		region = os.Getenv("AWS_DEFAULT_REGION")
	}

	// If no region is set, try to get it from EKS
	if region == "" {
		if cluster := os.Getenv("CLUSTER_NAME"); cluster != "" {
			// Get region from cluster name (assuming format: <region>.<cluster>)
			parts := strings.Split(cluster, ".")
			if len(parts) > 0 {
				region = parts[0]
			}
		}
	}

	// Load AWS config with region if specified
	opts := []func(*config.LoadOptions) error{
		config.WithSharedConfigProfile(""),
	}
	if region != "" {
		opts = append(opts, config.WithRegion(region))
	}

	cfg, err := config.LoadDefaultConfig(context.Background(), opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS config: %v", err)
	}

	// If still no region, return error
	if cfg.Region == "" {
		return nil, fmt.Errorf("no AWS region specified. Please set AWS_REGION environment variable or configure region in ~/.aws/config")
	}

	return &Client{
		iamClient: iam.NewFromConfig(cfg),
	}, nil
}

func maskSecret(s string) string {
	if len(s) > 4 {
		return s[:4] + "..."
	}
	return "not set"
}

func getRoleNameFromARN(arn string) string {
	// Simple implementation - you might want to make this more robust
	parts := strings.Split(arn, "/")
	return parts[len(parts)-1]
}

func isHighRiskService(action string) bool {
	highRiskServices := []string{
		"iam:",
		"kms:",
		"secretsmanager:",
		"lambda:",
		"ec2:",
		"rds:",
		"dynamodb:",
	}

	for _, service := range highRiskServices {
		if strings.HasPrefix(action, service) {
			return true
		}
	}

	// Also consider any action with full service access (*) as high risk
	if strings.HasSuffix(action, ":*") {
		return true
	}

	return false
}
