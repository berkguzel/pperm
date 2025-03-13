package printer

import (
	"testing"

	"github.com/berkguzel/pperm/internal/options"
	"github.com/berkguzel/pperm/pkg/types"
	"github.com/stretchr/testify/assert"
)

func TestPrint(t *testing.T) {
	tests := []struct {
		name           string
		podPerms       []types.PodPermissions
		opts           *options.Options
		expectedOutput string
	}{
		{
			name: "single policy overview",
			podPerms: []types.PodPermissions{
				{
					PodName:        "test-pod",
					Namespace:      "default",
					ServiceAccount: "test-sa",
					IAMRole:        "test-role",
					Policies: []types.Policy{
						{
							Name: "TestPolicy",
							Arn:  "arn:aws:iam::test-policy",
							Permissions: []types.PermissionDisplay{
								{
									Action:       "s3:GetObject",
									Resource:     "arn:aws:s3:::my-bucket/*",
									Effect:       "Allow",
									IsBroad:      false,
									IsHighRisk:   false,
									HasCondition: false,
								},
							},
						},
					},
				},
			},
			opts:           &options.Options{},
			expectedOutput: "POLICY NAME",
		},
		{
			name:     "empty permissions",
			podPerms: []types.PodPermissions{},
			opts:     &options.Options{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := Print(tt.podPerms, tt.opts)
			assert.NoError(t, err)
		})
	}
}

func TestDetermineAccessLevel(t *testing.T) {
	tests := []struct {
		name        string
		permissions []types.PermissionDisplay
		policyName  string
		expected    string
	}{
		{
			name: "full access",
			permissions: []types.PermissionDisplay{
				{Action: "s3:*"},
			},
			policyName: "test-policy",
			expected:   "Full Access",
		},
		{
			name: "read only",
			permissions: []types.PermissionDisplay{
				{Action: "s3:Get*"},
				{Action: "s3:List*"},
				{Action: "s3:Describe*"},
			},
			policyName: "ReadOnlyPolicy",
			expected:   "Read-Only",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := determineAccessLevel(tt.permissions, tt.policyName)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestDetermineResourceScope(t *testing.T) {
	tests := []struct {
		name        string
		permissions []types.PermissionDisplay
		expected    string
	}{
		{
			name: "wildcard resource",
			permissions: []types.PermissionDisplay{
				{Resource: "*"},
			},
			expected: "*",
		},
		{
			name: "single resource",
			permissions: []types.PermissionDisplay{
				{Resource: "arn:aws:s3:::my-bucket"},
			},
			expected: "Single",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := determineResourceScope(tt.permissions)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestDetermineConditions(t *testing.T) {
	tests := []struct {
		name     string
		policy   types.Policy
		expected string
	}{
		{
			name: "with conditions",
			policy: types.Policy{
				Permissions: []types.PermissionDisplay{
					{HasCondition: true},
					{HasCondition: false},
				},
			},
			expected: "Yes",
		},
		{
			name: "no conditions",
			policy: types.Policy{
				Permissions: []types.PermissionDisplay{
					{HasCondition: false},
					{HasCondition: false},
				},
			},
			expected: "No",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := determineConditions(tt.policy)
			assert.Equal(t, tt.expected, result)
		})
	}
}
