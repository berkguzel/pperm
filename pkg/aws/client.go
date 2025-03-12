package aws

import (
	"context"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/iam"
)

type Client struct {
	iamClient *iam.Client
}

func NewClient() (*Client, error) {
	cfg, err := config.LoadDefaultConfig(context.Background(),
		config.WithSharedConfigProfile(""),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS config: %v", err)
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
