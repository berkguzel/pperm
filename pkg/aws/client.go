package aws

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/iam"
)

type Client struct {
	iamClient *iam.Client
}

func NewClient() (*Client, error) {
	cfg, err := config.LoadDefaultConfig(context.Background())
	if err != nil {
		return nil, err
	}

	return &Client{
		iamClient: iam.NewFromConfig(cfg),
	}, nil
}

func getRoleNameFromARN(arn string) string {
	// Simple implementation - you might want to make this more robust
	parts := strings.Split(arn, "/")
	return parts[len(parts)-1]
}

func (c *Client) GetPolicyPermissions(ctx context.Context, policyArn string) ([]Permission, error) {
	// Get the policy version
	policy, err := c.iamClient.GetPolicy(ctx, &iam.GetPolicyInput{
		PolicyArn: &policyArn,
	})
	if err != nil {
		return nil, err
	}

	// Get the policy version details
	policyVersion, err := c.iamClient.GetPolicyVersion(ctx, &iam.GetPolicyVersionInput{
		PolicyArn: &policyArn,
		VersionId: policy.Policy.DefaultVersionId,
	})
	if err != nil {
		return nil, err
	}

	// Parse policy document
	var doc PolicyDocument
	if err := json.Unmarshal([]byte(*policyVersion.PolicyVersion.Document), &doc); err != nil {
		return nil, err
	}

	return formatPermissions(doc.Statement), nil
}

func formatPermissions(statements []Statement) []Permission {
	var permissions []Permission

	for _, stmt := range statements {
		for _, action := range stmt.Action {
			for _, resource := range stmt.Resource {
				perm := Permission{
					Action:     action,
					Resource:   resource,
					Effect:     stmt.Effect,
					IsBroad:    strings.Contains(action, "*") || strings.Contains(resource, "*"),
					IsHighRisk: isHighRiskPermission(action),
				}
				permissions = append(permissions, perm)
			}
		}
	}

	return permissions
}

func isHighRiskPermission(action string) bool {
	highRiskPatterns := []string{
		"iam:",
		"kms:",
		"secretsmanager:",
		"ec2:*",
		"rds:*",
		"dynamodb:*",
	}

	for _, pattern := range highRiskPatterns {
		if strings.Contains(action, pattern) {
			return true
		}
	}
	return false
}
