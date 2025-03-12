package printer

import (
	"fmt"
	"strings"

	"github.com/berkguzel/pperm/pkg/types"
	"github.com/fatih/color"
)

var (
	green     = color.New(color.FgGreen).SprintFunc()
	yellow    = color.New(color.FgYellow).SprintFunc()
	red       = color.New(color.FgRed).SprintFunc()
	bold      = color.New(color.Bold).SprintFunc()
	checkmark = green("✅")
	warning   = yellow("⚠️")
	danger    = red("❌")
)

func PrintPermissions(permissions []types.PodPermissions) {
	for _, podPerm := range permissions {
		fmt.Printf("\n%s Pod: %s (Namespace: %s)\n", bold("→"), podPerm.PodName, podPerm.Namespace)
		fmt.Printf("  Service Account: %s\n", podPerm.ServiceAccount)
		fmt.Printf("  IAM Role: %s\n", podPerm.IAMRole)

		for _, policy := range podPerm.Policies {
			fmt.Printf("\n  Policy: %s\n", policy.Name)
			fmt.Printf("  ARN: %s\n", policy.Arn)
			fmt.Printf("  Permissions:\n")

			for _, perm := range policy.Permissions {
				icon := checkmark
				if perm.IsHighRisk {
					icon = danger
				} else if perm.IsBroad {
					icon = warning
				}

				resource := perm.Resource
				if resource == "*" {
					resource = "all resources"
				}

				desc := ""
				if perm.IsBroad {
					if strings.HasSuffix(perm.Action, ":*") {
						desc = " (broad permissions)"
					}
					if perm.Resource == "*" {
						desc = " (all resources)"
					}
				}

				fmt.Printf("    %s %-30s on %s%s\n",
					icon,
					perm.Action,
					resource,
					desc,
				)
			}
		}
	}
}

func printPermissionLine(perm types.PermissionDisplay) {
	var icon string
	var description string

	switch {
	case perm.IsHighRisk:
		icon = danger
	case perm.IsBroad:
		icon = warning
	default:
		icon = checkmark
	}

	// Format the resource string
	resourceStr := formatResource(perm.Resource)

	// Add description for broad permissions
	if perm.IsBroad {
		if strings.HasSuffix(perm.Action, ":*") {
			description = " (broad permissions)"
		}
		if perm.Resource == "*" {
			description = " (all resources)"
		}
	}

	// Pad the action string for alignment
	actionPadded := fmt.Sprintf("%-20s", perm.Action)

	fmt.Printf("    %s %s on %s%s\n",
		icon,
		actionPadded,
		resourceStr,
		description,
	)
}

// Helper function to format permission details
func formatPermissionDetails(action, resource string) string {
	if strings.HasSuffix(action, ":*") {
		return fmt.Sprintf("%s %s on %s (broad permissions)",
			warning,
			action,
			formatResource(resource),
		)
	}
	return fmt.Sprintf("%s %s on %s",
		checkmark,
		action,
		formatResource(resource),
	)
}

func formatResource(resource string) string {
	switch resource {
	case "*":
		return "all resources"
	default:
		return resource
	}
}
