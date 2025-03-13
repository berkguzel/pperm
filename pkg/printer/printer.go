package printer

import (
	"fmt"
	"io"
	"strings"

	"github.com/berkguzel/pperm/internal/options"
	"github.com/berkguzel/pperm/pkg/types"
)

type Printer struct {
	writer io.Writer
}

func New(w io.Writer) *Printer {
	return &Printer{writer: w}
}

func Print(perms []types.PodPermissions, opts *options.Options) error {
	if opts.InspectPolicy {
		return inspectPolicy(perms, opts)
	}

	if opts.ShowPerms || opts.RiskOnly {
		// Calculate max resource length
		maxResourceLen := 52 // minimum width
		for _, perm := range perms {
			for _, policy := range perm.Policies {
				for _, p := range policy.Permissions {
					if len(p.Resource) > maxResourceLen {
						maxResourceLen = len(p.Resource) + 2 // add some padding
					}
				}
			}
		}

		// Print table header with separator
		printPermissionsTableHeader(maxResourceLen)

		// Print permissions
		for _, perm := range perms {
			for _, policy := range perm.Policies {
				for _, p := range policy.Permissions {
					scope := " ✅ "
					if p.IsBroad || p.IsHighRisk {
						scope = " 🚨 "
					}

					// Skip if risk-only flag is set and permission doesn't have broad scope
					if opts.RiskOnly && scope != " 🚨 " {
						continue
					}

					fmt.Printf("| %-30s | %-35s | %-*s | %-4s |\n",
						truncateString(policy.Name, 30),
						p.Action,
						maxResourceLen,
						p.Resource,
						scope,
					)
				}
			}
		}

		// Print table footer
		printPermissionsSeparator(maxResourceLen)
		return nil
	}

	// Default case: show policy overview table
	printPolicyTableHeader()

	for _, perm := range perms {
		for _, policy := range perm.Policies {
			// Skip if risk-only flag is set and no high-risk permissions
			if opts.RiskOnly {
				hasRisk := false
				for _, p := range policy.Permissions {
					if p.IsBroad || p.IsHighRisk {
						hasRisk = true
						break
					}
				}
				if !hasRisk {
					continue
				}
			}

			// Determine access level based on permissions and policy name
			accessLevel := determineAccessLevel(policy.Permissions, policy.Name)
			// Determine service based on actions in permissions
			service := determineService(policy.Permissions)
			// Determine resource scope
			resource := determineResourceScope(policy.Permissions)
			// Determine if there are conditions
			condition := determineConditions(policy)

			fmt.Printf("| %-30s | %-7s | %-14s | %-10s | %-12s |\n",
				truncateString(policy.Name, 30),
				truncateString(service, 7),
				truncateString(accessLevel, 14),
				truncateString(resource, 10),
				truncateString(condition, 12),
			)
		}
	}

	printPolicySeparator()
	return nil
}

func determineAccessLevel(permissions []types.PermissionDisplay, policyName string) string {
	hasFullAccess := false
	hasLimitedAccess := false
	readOnly := true

	// First check if the policy name itself indicates full access
	policyNameLower := strings.ToLower(policyName)
	if strings.Contains(policyNameLower, "readonly") {
		return "Read-Only"
	}
	if strings.Contains(policyNameLower, "fullaccesss") ||
		strings.Contains(policyNameLower, "full-access") ||
		strings.Contains(policyNameLower, "fullaccess") {
		hasFullAccess = true
	}

	for _, p := range permissions {
		action := strings.ToLower(p.Action)

		// Check for full access indicators
		if action == "*" || strings.HasSuffix(action, ":*") {
			hasFullAccess = true
			continue
		}

		// Check for read-only actions
		if strings.HasPrefix(action, "get") ||
			strings.HasPrefix(action, "list") ||
			strings.HasPrefix(action, "describe") ||
			strings.HasPrefix(action, "head") {
			continue
		}

		// If we get here, it's a write/modify action
		hasLimitedAccess = true
		readOnly = false
	}

	// If we have any limited access actions, the whole policy is limited
	if hasLimitedAccess {
		return "Limited Access"
	}

	// If we have full access and no limited actions
	if hasFullAccess {
		return "Full Access"
	}

	// If all actions are read-only
	if readOnly {
		return "Read-Only"
	}

	return "Limited Access"
}

func determineService(permissions []types.PermissionDisplay) string {
	if len(permissions) == 0 {
		return "Unknown"
	}
	// Extract service from the first action (e.g., "ec2:DescribeInstances" -> "EC2")
	parts := strings.Split(permissions[0].Action, ":")
	if len(parts) > 0 {
		return strings.ToUpper(parts[0])
	}
	return "Unknown"
}

func determineResourceScope(permissions []types.PermissionDisplay) string {
	hasWildcard := false
	resourceCount := make(map[string]bool)

	for _, p := range permissions {
		resourceCount[p.Resource] = true
		if strings.Contains(p.Resource, "*") {
			hasWildcard = true
		}
	}

	if hasWildcard {
		return "*"
	} else if len(resourceCount) > 1 {
		return "Multiple"
	}
	return "Single"
}

func determineConditions(policy types.Policy) string {
	hasConditions := false
	for _, perm := range policy.Permissions {
		if perm.HasCondition {
			hasConditions = true
			break
		}
	}

	if hasConditions {
		return "Yes"
	}
	return "No"
}

func truncateString(s string, maxLen int) string {
	if len(s) > maxLen {
		return s[:maxLen-3] + "..."
	}
	return s
}

func printPolicyTableHeader() {
	printPolicySeparator()
	fmt.Printf("| %-30s | %-7s | %-14s | %-10s | %-12s |\n",
		"POLICY NAME",
		"SERVICE",
		"ACCESS LEVEL",
		"RESOURCE",
		"CONDITION",
	)
	printPolicySeparator()
}

func printPolicySeparator() {
	fmt.Println("+--------------------------------+---------+----------------+------------+--------------+")
}

func printPermissionsTableHeader(resourceWidth int) {
	printPermissionsSeparator(resourceWidth)
	fmt.Printf("| %-30s | %-35s | %-*s | %-5s |\n",
		"POLICY",
		"ACTION",
		resourceWidth,
		"RESOURCE",
		"SCOPE",
	)
	printPermissionsSeparator(resourceWidth)
}

func printPermissionsSeparator(resourceWidth int) {
	fmt.Printf("+--------------------------------+-------------------------------------+%s+-------+\n",
		strings.Repeat("-", resourceWidth+2))
}

func padRight(str string, length int) string {
	if len(str) >= length {
		return str[:length-1] + " "
	}
	return str + strings.Repeat(" ", length-len(str))
}

func centerText(text string, width int) string {
	if len(text) >= width {
		return text
	}
	leftPad := (width - len(text)) / 2
	rightPad := width - len(text) - leftPad
	return strings.Repeat(" ", leftPad) + text + strings.Repeat(" ", rightPad)
}

func inspectPolicy(perms []types.PodPermissions, opts *options.Options) error {
	if len(perms) == 0 {
		fmt.Println("No pod permissions found")
		return nil
	}

	pod := perms[0]
	fmt.Printf("\nPod: %s\n", pod.PodName)
	fmt.Printf("Service Account: %s\n", pod.ServiceAccount)
	fmt.Printf("IAM Role: %s\n\n", pod.IAMRole)

	if len(pod.Policies) == 0 {
		fmt.Println("No policies attached to this pod")
		return nil
	}

	// Display policy selection menu
	fmt.Println("Available Policies:")
	fmt.Println("------------------")
	for i, policy := range pod.Policies {
		fmt.Printf("%d. %s\n", i+1, policy.Name)
	}

	// Get user selection
	var choice int
	fmt.Print("\nEnter policy number to inspect (or 0 to exit): ")
	fmt.Scanf("%d", &choice)

	if choice == 0 || choice > len(pod.Policies) {
		return nil
	}

	// Display selected policy details
	selectedPolicy := pod.Policies[choice-1]
	fmt.Printf("\nPolicy: %s\n", selectedPolicy.Name)
	fmt.Printf("ARN: %s\n\n", selectedPolicy.Arn)

	// Calculate max resource length
	maxResourceLen := 52 // minimum width
	for _, p := range selectedPolicy.Permissions {
		if len(p.Resource) > maxResourceLen {
			maxResourceLen = len(p.Resource) + 2 // add some padding
		}
	}

	// Print permissions table
	fmt.Println("Permissions:")
	fmt.Println("-----------")
	printPermissionsTableHeader(maxResourceLen)

	for _, p := range selectedPolicy.Permissions {
		scope := " ✅ "
		if p.IsBroad || p.IsHighRisk {
			scope = " 🚨 "
		}

		// Skip if risk-only flag is set and permission doesn't have broad scope
		if opts.RiskOnly && scope != " 🚨 " {
			continue
		}

		fmt.Printf("| %-30s | %-35s | %-*s | %-4s |\n",
			truncateString(selectedPolicy.Name, 30),
			p.Action,
			maxResourceLen,
			p.Resource,
			scope,
		)
	}

	printPermissionsSeparator(maxResourceLen)

	// Show additional policy information
	fmt.Printf("\nAccess Level: %s\n", determineAccessLevel(selectedPolicy.Permissions, selectedPolicy.Name))
	fmt.Printf("Service: %s\n", determineService(selectedPolicy.Permissions))
	fmt.Printf("Resource Scope: %s\n", determineResourceScope(selectedPolicy.Permissions))
	fmt.Printf("Has Conditions: %s\n", determineConditions(selectedPolicy))

	return nil
}
