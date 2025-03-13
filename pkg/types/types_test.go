package types

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPermissionDisplay_String(t *testing.T) {
	tests := []struct {
		name     string
		perm     PermissionDisplay
		expected string
	}{
		{
			name: "full permission display",
			perm: PermissionDisplay{
				Action:       "s3:GetObject",
				Resource:     "arn:aws:s3:::my-bucket/*",
				Effect:       "Allow",
				IsBroad:      true,
				IsHighRisk:   true,
				HasCondition: true,
			},
			expected: "Allow s3:GetObject on arn:aws:s3:::my-bucket/* (Broad: true, High Risk: true, Has Condition: true)",
		},
		{
			name: "minimal permission display",
			perm: PermissionDisplay{
				Action:   "s3:GetObject",
				Resource: "arn:aws:s3:::my-bucket/*",
				Effect:   "Allow",
			},
			expected: "Allow s3:GetObject on arn:aws:s3:::my-bucket/* (Broad: false, High Risk: false, Has Condition: false)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.perm.String()
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestPolicy_String(t *testing.T) {
	tests := []struct {
		name     string
		policy   Policy
		expected string
	}{
		{
			name: "policy with permissions",
			policy: Policy{
				Name: "TestPolicy",
				Arn:  "arn:aws:iam::test-policy",
				Permissions: []PermissionDisplay{
					{
						Action:   "s3:GetObject",
						Resource: "arn:aws:s3:::my-bucket/*",
						Effect:   "Allow",
					},
				},
			},
			expected: "Policy: TestPolicy (arn:aws:iam::test-policy) with 1 permissions",
		},
		{
			name: "policy without permissions",
			policy: Policy{
				Name: "EmptyPolicy",
				Arn:  "arn:aws:iam::empty-policy",
			},
			expected: "Policy: EmptyPolicy (arn:aws:iam::empty-policy) with 0 permissions",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.policy.String()
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestPodPermissions_String(t *testing.T) {
	tests := []struct {
		name     string
		podPerms PodPermissions
		expected string
	}{
		{
			name: "pod permissions with policies",
			podPerms: PodPermissions{
				PodName:        "test-pod",
				Namespace:      "default",
				ServiceAccount: "test-sa",
				IAMRole:        "test-role",
				Policies: []Policy{
					{
						Name: "TestPolicy",
						Arn:  "arn:aws:iam::test-policy",
					},
				},
			},
			expected: "Pod: test-pod in namespace default using service account test-sa with IAM role test-role (1 policies)",
		},
		{
			name: "pod permissions without policies",
			podPerms: PodPermissions{
				PodName:        "test-pod",
				Namespace:      "default",
				ServiceAccount: "test-sa",
				IAMRole:        "test-role",
			},
			expected: "Pod: test-pod in namespace default using service account test-sa with IAM role test-role (0 policies)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.podPerms.String()
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestPermissionDisplay(t *testing.T) {
	perm := PermissionDisplay{
		Action:   "s3:GetObject",
		Resource: "arn:aws:s3:::my-bucket/*",
		Effect:   "Allow",
	}

	assert.Equal(t, "s3:GetObject", perm.Action)
	assert.Equal(t, "arn:aws:s3:::my-bucket/*", perm.Resource)
	assert.Equal(t, "Allow", perm.Effect)
	assert.False(t, perm.IsBroad)
	assert.False(t, perm.IsHighRisk)
	assert.False(t, perm.HasCondition)
}

func TestPolicy(t *testing.T) {
	policy := Policy{
		Name: "TestPolicy",
		Arn:  "arn:aws:iam::test-policy",
		Permissions: []PermissionDisplay{
			{
				Action:   "s3:GetObject",
				Resource: "arn:aws:s3:::my-bucket/*",
				Effect:   "Allow",
			},
		},
	}

	assert.Equal(t, "TestPolicy", policy.Name)
	assert.Equal(t, "arn:aws:iam::test-policy", policy.Arn)
	assert.Len(t, policy.Permissions, 1)
}

func TestPodPermissions(t *testing.T) {
	pod := PodPermissions{
		PodName:        "test-pod",
		Namespace:      "default",
		ServiceAccount: "test-sa",
		IAMRole:        "test-role",
	}

	assert.Equal(t, "test-pod", pod.PodName)
	assert.Equal(t, "default", pod.Namespace)
	assert.Equal(t, "test-sa", pod.ServiceAccount)
	assert.Equal(t, "test-role", pod.IAMRole)
	assert.Empty(t, pod.Policies)
}
