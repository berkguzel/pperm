package aws

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/berkguzel/pperm/pkg/types"
)

func convertPolicyDocument(name, arn string, perms []types.PermissionDisplay) types.Policy {
	return types.Policy{
		Name:        name,
		Arn:         arn,
		Permissions: perms,
	}
}

func (c *Client) GetRolePolicies(ctx context.Context, roleArn string) ([]types.Policy, error) {
	roleName := getRoleNameFromARN(roleArn)
	var policies []types.Policy

	result, err := c.iamClient.ListAttachedRolePolicies(ctx, &iam.ListAttachedRolePoliciesInput{
		RoleName: &roleName,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to list policies: %v", err)
	}

	for _, policy := range result.AttachedPolicies {
		perms, err := c.GetPolicyPermissions(ctx, *policy.PolicyArn)
		if err != nil {
			fmt.Printf("Error getting permissions for policy %s: %v\n", *policy.PolicyArn, err)
			continue
		}

		policies = append(policies, types.Policy{
			Name:        *policy.PolicyName,
			Arn:         *policy.PolicyArn,
			Permissions: perms,
		})
	}

	return policies, nil
}

// Only call this when permissions are needed
func (c *Client) GetPolicyPermissions(ctx context.Context, policyArn string) ([]types.PermissionDisplay, error) {
	policy, err := c.iamClient.GetPolicy(ctx, &iam.GetPolicyInput{
		PolicyArn: &policyArn,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get policy: %v", err)
	}

	policyVersion, err := c.iamClient.GetPolicyVersion(ctx, &iam.GetPolicyVersionInput{
		PolicyArn: &policyArn,
		VersionId: policy.Policy.DefaultVersionId,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get policy version: %v", err)
	}

	decodedDoc, err := url.QueryUnescape(*policyVersion.PolicyVersion.Document)
	if err != nil {
		return nil, fmt.Errorf("failed to decode policy document: %v", err)
	}

	var doc PolicyDocument
	if err := json.Unmarshal([]byte(decodedDoc), &doc); err != nil {
		return nil, fmt.Errorf("failed to parse policy document: %v", err)
	}

	return formatPermissions(doc.Statement), nil
}

func formatPermissions(statements []Statement) []types.PermissionDisplay {
	var permissions []types.PermissionDisplay

	for _, stmt := range statements {
		actions := getActions(stmt.Action)
		resources := getResources(stmt.Resource)
		hasCondition := len(stmt.Condition) > 0

		for _, action := range actions {
			for _, resource := range resources {
				isBroad := strings.Contains(action, "*") || strings.Contains(resource, "*")
				isHighRisk := isHighRiskService(action)

				permissions = append(permissions, types.PermissionDisplay{
					Action:       action,
					Resource:     resource,
					Effect:       stmt.Effect,
					IsBroad:      isBroad,
					IsHighRisk:   isHighRisk,
					HasCondition: hasCondition,
				})
			}
		}
	}

	return permissions
}
