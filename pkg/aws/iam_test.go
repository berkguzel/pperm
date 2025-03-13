package aws

import (
	"context"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/berkguzel/pperm/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// MockIAMClient mocks the IAM client for testing
type MockIAMClient struct {
	mock.Mock
}

func (m *MockIAMClient) GetPolicy(ctx context.Context, input *iam.GetPolicyInput, opts ...func(*iam.Options)) (*iam.GetPolicyOutput, error) {
	args := m.Called(ctx, input)
	return args.Get(0).(*iam.GetPolicyOutput), args.Error(1)
}

func (m *MockIAMClient) GetPolicyVersion(ctx context.Context, input *iam.GetPolicyVersionInput, opts ...func(*iam.Options)) (*iam.GetPolicyVersionOutput, error) {
	args := m.Called(ctx, input)
	return args.Get(0).(*iam.GetPolicyVersionOutput), args.Error(1)
}

func (m *MockIAMClient) ListAttachedRolePolicies(ctx context.Context, input *iam.ListAttachedRolePoliciesInput, opts ...func(*iam.Options)) (*iam.ListAttachedRolePoliciesOutput, error) {
	args := m.Called(ctx, input)
	return args.Get(0).(*iam.ListAttachedRolePoliciesOutput), args.Error(1)
}

func TestGetRolePolicies(t *testing.T) {
	mockClient := &MockIAMClient{}
	client := &Client{iamClient: mockClient}

	mockClient.On("ListAttachedRolePolicies", mock.Anything, &iam.ListAttachedRolePoliciesInput{
		RoleName: aws.String("test-role"),
	}).Return(&iam.ListAttachedRolePoliciesOutput{
		AttachedPolicies: []iamtypes.AttachedPolicy{
			{
				PolicyName: aws.String("test-policy"),
				PolicyArn:  aws.String("arn:aws:iam::123456789012:policy/test-policy"),
			},
		},
	}, nil)

	mockClient.On("GetPolicy", mock.Anything, &iam.GetPolicyInput{
		PolicyArn: aws.String("arn:aws:iam::123456789012:policy/test-policy"),
	}).Return(&iam.GetPolicyOutput{
		Policy: &iamtypes.Policy{
			DefaultVersionId: aws.String("v1"),
		},
	}, nil)

	mockClient.On("GetPolicyVersion", mock.Anything, &iam.GetPolicyVersionInput{
		PolicyArn: aws.String("arn:aws:iam::123456789012:policy/test-policy"),
		VersionId: aws.String("v1"),
	}).Return(&iam.GetPolicyVersionOutput{
		PolicyVersion: &iamtypes.PolicyVersion{
			Document: aws.String(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:GetObject"],"Resource":["*"]}]}`),
		},
	}, nil)

	policies, err := client.GetRolePolicies(context.Background(), "test-role")
	assert.NoError(t, err)
	assert.Len(t, policies, 1)
	assert.Equal(t, "test-policy", policies[0].Name)
}

func TestGetPolicyPermissions(t *testing.T) {
	mockClient := &MockIAMClient{}
	client := &Client{iamClient: mockClient}

	policyArn := "arn:aws:iam::123456789012:policy/test-policy"
	mockClient.On("GetPolicy", mock.Anything, &iam.GetPolicyInput{
		PolicyArn: aws.String(policyArn),
	}).Return(&iam.GetPolicyOutput{
		Policy: &iamtypes.Policy{
			DefaultVersionId: aws.String("v1"),
		},
	}, nil)

	mockClient.On("GetPolicyVersion", mock.Anything, &iam.GetPolicyVersionInput{
		PolicyArn: aws.String(policyArn),
		VersionId: aws.String("v1"),
	}).Return(&iam.GetPolicyVersionOutput{
		PolicyVersion: &iamtypes.PolicyVersion{
			Document: aws.String(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:GetObject"],"Resource":["*"]}]}`),
		},
	}, nil)

	perms, err := client.GetPolicyPermissions(context.Background(), policyArn)
	assert.NoError(t, err)
	assert.Len(t, perms, 1)
	assert.Equal(t, "s3:GetObject", perms[0].Action)
	assert.Equal(t, "*", perms[0].Resource)
	assert.Equal(t, "Allow", perms[0].Effect)
}

func TestCache(t *testing.T) {
	cache := &Cache{
		items: make(map[string]cacheEntry),
	}

	t.Run("cache operations", func(t *testing.T) {
		key := "test-key"
		entry := cacheEntry{
			permissions: []types.PermissionDisplay{
				{
					Action:   "s3:GetObject",
					Resource: "arn:aws:s3:::my-bucket/*",
					Effect:   "Allow",
				},
			},
			timestamp: time.Now(),
		}

		// Set the entry
		cache.items[key] = entry

		// Get the entry
		result, ok := cache.Get(key)
		assert.True(t, ok)
		assert.Equal(t, entry.permissions, result.permissions)

		// Test expiration
		time.Sleep(time.Second)
		cache.items[key] = cacheEntry{
			permissions: entry.permissions,
			timestamp:   time.Now().Add(-25 * time.Hour), // Expired
		}
		_, ok = cache.Get(key)
		assert.False(t, ok)
	})
}

func TestGetRoleNameFromARN(t *testing.T) {
	tests := []struct {
		name     string
		arn      string
		expected string
	}{
		{
			name:     "simple role name",
			arn:      "arn:aws:iam::123456789012:role/test-role",
			expected: "test-role",
		},
		{
			name:     "role name with path",
			arn:      "arn:aws:iam::123456789012:role/path/to/test-role",
			expected: "test-role",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := getRoleNameFromARN(tt.arn)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestMaskSecret(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "long secret",
			input:    "mysupersecretkey",
			expected: "mysu...",
		},
		{
			name:     "short secret",
			input:    "key",
			expected: "not set",
		},
		{
			name:     "empty secret",
			input:    "",
			expected: "not set",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := maskSecret(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestIsHighRiskService(t *testing.T) {
	tests := []struct {
		name     string
		action   string
		expected bool
	}{
		{
			name:     "iam service",
			action:   "iam:CreateRole",
			expected: true,
		},
		{
			name:     "kms service",
			action:   "kms:CreateKey",
			expected: true,
		},
		{
			name:     "s3 service",
			action:   "s3:GetObject",
			expected: false,
		},
		{
			name:     "wildcard action",
			action:   "s3:*",
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isHighRiskService(tt.action)
			assert.Equal(t, tt.expected, result)
		})
	}
}
