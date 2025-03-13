package printer

import (
	"testing"

	"github.com/berkguzel/pperm/pkg/types"
	"github.com/stretchr/testify/assert"
)

func TestFormatResource(t *testing.T) {
	tests := []struct {
		name     string
		resource string
		want     string
	}{
		{
			name:     "wildcard resource",
			resource: "*",
			want:     "all resources",
		},
		{
			name:     "specific resource",
			resource: "arn:aws:s3:::my-bucket",
			want:     "arn:aws:s3:::my-bucket",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := formatResource(tt.resource)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestFormatPermissionDetails(t *testing.T) {
	tests := []struct {
		name         string
		action       string
		resource     string
		wantContains []string
	}{
		{
			name:     "broad permission",
			action:   "s3:*",
			resource: "arn:aws:s3:::my-bucket",
			wantContains: []string{
				"s3:*",
				"arn:aws:s3:::my-bucket",
				"broad permissions",
			},
		},
		{
			name:     "specific permission",
			action:   "s3:GetObject",
			resource: "arn:aws:s3:::my-bucket",
			wantContains: []string{
				"s3:GetObject",
				"arn:aws:s3:::my-bucket",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := formatPermissionDetails(tt.action, tt.resource)
			for _, want := range tt.wantContains {
				assert.Contains(t, got, want)
			}
		})
	}
}

func TestPrintPermissionLine(t *testing.T) {
	tests := []struct {
		name string
		perm types.PermissionDisplay
	}{
		{
			name: "high risk permission",
			perm: types.PermissionDisplay{
				Action:     "iam:*",
				Resource:   "*",
				IsHighRisk: true,
				IsBroad:    true,
			},
		},
		{
			name: "broad permission",
			perm: types.PermissionDisplay{
				Action:     "s3:*",
				Resource:   "arn:aws:s3:::my-bucket/*",
				IsHighRisk: false,
				IsBroad:    true,
			},
		},
		{
			name: "safe permission",
			perm: types.PermissionDisplay{
				Action:     "s3:GetObject",
				Resource:   "arn:aws:s3:::my-bucket/specific-path",
				IsHighRisk: false,
				IsBroad:    false,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// This is a visual test, we just ensure it doesn't panic
			printPermissionLine(tt.perm)
		})
	}
}
