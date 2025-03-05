package printer

import (
	"fmt"

	"github.com/berkguzel/pperm/internal/options"
	"github.com/berkguzel/pperm/pkg/types"
)

func Print(perms []types.PodPermissions, opts *options.Options) error {
	for _, perm := range perms {
		// Show only role
		if opts.ShowRole {
			fmt.Println(perm.IAMRole)
			return nil
		}

		// Show only policies
		if opts.ShowPolicies {
			fmt.Printf("Policies attached to pod %s:\n", perm.PodName)
			for _, policy := range perm.Policies {
				fmt.Printf("• %s\n  %s\n", policy.Name, policy.Arn)
			}
			return nil
		}

		// Show detailed permissions
		if opts.ShowPerms {
			fmt.Printf("Permissions for pod %s:\n", perm.PodName)
			for _, policy := range perm.Policies {
				fmt.Printf("\nPolicy: %s\n", policy.Name)
				printPermissions(policy.Permissions)
			}
			return nil
		}

		// Normal summary
		fmt.Printf("\n→ Pod: %s (Namespace: %s)\n", perm.PodName, perm.Namespace)
		fmt.Printf("  Service Account: %s\n", perm.ServiceAccount)
		fmt.Printf("  IAM Role: %s\n", perm.IAMRole)
		fmt.Printf("\n  Attached Policies:\n")
		for _, policy := range perm.Policies {
			fmt.Printf("  • %s\n    %s\n", policy.Name, policy.Arn)
		}
	}
	return nil
}

func printPermissions(perms []types.PermissionDisplay) {
	for _, perm := range perms {
		var icon string
		switch {
		case perm.IsHighRisk:
			icon = "❗"
		case perm.IsBroad:
			icon = "⚠️"
		default:
			icon = "✅"
		}

		fmt.Printf("%s %-30s on %s\n",
			icon,
			perm.Action,
			formatResourceString(perm.Resource),
		)
	}
}

func formatResourceString(resource string) string {
	if resource == "*" {
		return "all resources"
	}
	return resource
}
