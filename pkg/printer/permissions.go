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
	for _, perm := range permissions {
		fmt.Printf("\n%s Pod: %s (Namespace: %s)\n", bold("→"), perm.PodName, perm.Namespace)
		fmt.Printf("  IAM Role: %s\n", perm.IAMRole)

		for _, policy := range perm.Policies {
			fmt.Printf("\n  Policy: %s\n", policy.Name)
			if policy.Arn != "" {
				fmt.Printf("  ARN: %s\n", policy.Arn)
			}

			fmt.Println("  Permissions:")
			for _, perm := range policy.Permissions {
				printPermissionLine(perm)
			}
		}
		fmt.Println()
	}
}

func printPermissionLine(perm types.PermissionDisplay) {
	var icon string

	switch {
	case perm.IsHighRisk:
		icon = danger
	case perm.IsBroad:
		icon = warning
	default:
		icon = checkmark
	}

	// Format the resource string
	resourceStr := perm.Resource
	if resourceStr == "*" {
		resourceStr = "all resources"
	}

	// Pad the action string for alignment
	actionPadded := fmt.Sprintf("%-20s", perm.Action)

	fmt.Printf("    %s %s on %s\n", icon, actionPadded, resourceStr)
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
	if resource == "*" {
		return "all resources"
	}
	return resource
}
