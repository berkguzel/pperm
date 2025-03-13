package analyzer

import (
	"testing"

	"github.com/berkguzel/pperm/pkg/types"
	"github.com/stretchr/testify/assert"
)

func TestProcessPermissions(t *testing.T) {
	analyzer := &Analyzer{}
	tests := []struct {
		name       string
		statements []types.StatementInfo
		want       []types.PermissionDisplay
	}{
		{
			name: "basic allow statement",
			statements: []types.StatementInfo{
				{
					Effect:    "Allow",
					Actions:   []string{"s3:GetObject"},
					Resources: []string{"arn:aws:s3:::my-bucket/*"},
				},
			},
			want: []types.PermissionDisplay{
				{
					Action:     "s3:GetObject",
					Resource:   "arn:aws:s3:::my-bucket/*",
					IsBroad:    false,
					IsHighRisk: false,
				},
			},
		},
		{
			name: "high risk permission",
			statements: []types.StatementInfo{
				{
					Effect:    "Allow",
					Actions:   []string{"s3:*"},
					Resources: []string{"*"},
				},
			},
			want: []types.PermissionDisplay{
				{
					Action:     "s3:*",
					Resource:   "*",
					IsBroad:    true,
					IsHighRisk: true,
				},
			},
		},
		{
			name: "deny statement is ignored",
			statements: []types.StatementInfo{
				{
					Effect:    "Deny",
					Actions:   []string{"s3:DeleteBucket"},
					Resources: []string{"*"},
				},
			},
			want: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := analyzer.processPermissions(tt.statements)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestIsHighRiskPermission(t *testing.T) {
	tests := []struct {
		name     string
		action   string
		resource string
		want     bool
	}{
		{
			name:     "high risk IAM with wildcard",
			action:   "iam:*",
			resource: "*",
			want:     true,
		},
		{
			name:     "high risk S3 with wildcard",
			action:   "s3:*",
			resource: "*",
			want:     true,
		},
		{
			name:     "specific action not high risk",
			action:   "s3:GetObject",
			resource: "*",
			want:     false,
		},
		{
			name:     "high risk pattern but specific resource",
			action:   "iam:*",
			resource: "arn:aws:iam::123456789012:role/specific-role",
			want:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isHighRiskPermission(tt.action, tt.resource)
			assert.Equal(t, tt.want, got)
		})
	}
}
