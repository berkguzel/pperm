package aws

import (
	"context"
	"encoding/json"

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

	// Get inline policies
	inlinePolicies, err := c.iamClient.ListRolePolicies(ctx, &iam.ListRolePoliciesInput{
		RoleName: &roleName,
	})
	if err != nil {
		return nil, err
	}

	for _, policyName := range inlinePolicies.PolicyNames {
		policy, err := c.iamClient.GetRolePolicy(ctx, &iam.GetRolePolicyInput{
			RoleName:   &roleName,
			PolicyName: &policyName,
		})
		if err != nil {
			continue
		}

		// Parse and format permissions
		var doc PolicyDocument
		if err := json.Unmarshal([]byte(*policy.PolicyDocument), &doc); err != nil {
			continue
		}
		perms := formatPermissions(doc.Statement)

		var displayPerms []types.PermissionDisplay
		for _, p := range perms {
			displayPerms = append(displayPerms, types.PermissionDisplay{
				Action:     p.Action,
				Resource:   p.Resource,
				IsBroad:    p.IsBroad,
				IsHighRisk: p.IsHighRisk,
			})
		}

		policies = append(policies, convertPolicyDocument(policyName, "", displayPerms))
	}

	// Get attached policies
	attachedPolicies, err := c.iamClient.ListAttachedRolePolicies(ctx, &iam.ListAttachedRolePoliciesInput{
		RoleName: &roleName,
	})
	if err != nil {
		return nil, err
	}

	for _, policy := range attachedPolicies.AttachedPolicies {
		perms, err := c.GetPolicyPermissions(ctx, *policy.PolicyArn)
		if err != nil {
			continue
		}

		var displayPerms []types.PermissionDisplay
		for _, p := range perms {
			displayPerms = append(displayPerms, types.PermissionDisplay{
				Action:     p.Action,
				Resource:   p.Resource,
				IsBroad:    p.IsBroad,
				IsHighRisk: p.IsHighRisk,
			})
		}

		policies = append(policies, types.Policy{
			Name:        *policy.PolicyName,
			Arn:         *policy.PolicyArn,
			Permissions: displayPerms,
		})
	}

	return policies, nil
}
