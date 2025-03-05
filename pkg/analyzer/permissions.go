package analyzer

import (
	"sort"
	"strings"

	"github.com/berkguzel/pperm/pkg/types"
)

func (a *Analyzer) processPermissions(statements []types.StatementInfo) []types.PermissionDisplay {
	var displays []types.PermissionDisplay

	for _, stmt := range statements {
		if stmt.Effect != "Allow" {
			continue
		}

		for _, action := range stmt.Actions {
			for _, resource := range stmt.Resources {
				display := types.PermissionDisplay{
					Action:     action,
					Resource:   resource,
					IsBroad:    strings.HasSuffix(action, ":*"),
					IsHighRisk: isHighRiskPermission(action, resource),
				}
				displays = append(displays, display)
			}
		}
	}

	// Sort permissions (broad/high-risk ones first)
	sort.Slice(displays, func(i, j int) bool {
		if displays[i].IsHighRisk != displays[j].IsHighRisk {
			return displays[i].IsHighRisk
		}
		if displays[i].IsBroad != displays[j].IsBroad {
			return displays[i].IsBroad
		}
		return displays[i].Action < displays[j].Action
	})

	return displays
}

func isHighRiskPermission(action, resource string) bool {
	highRiskPatterns := []string{
		"iam:*",
		"s3:*",
		"ec2:*",
		"rds:*",
		"dynamodb:*",
		"secretsmanager:*",
		"kms:*",
	}

	if resource == "*" {
		for _, pattern := range highRiskPatterns {
			if action == pattern {
				return true
			}
		}
	}

	return false
}
