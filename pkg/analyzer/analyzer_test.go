package analyzer

import (
	"context"
	"testing"

	"github.com/berkguzel/pperm/internal/options"
	"github.com/berkguzel/pperm/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// Mock K8s Client
type MockK8sClient struct {
	mock.Mock
}

func (m *MockK8sClient) GetPod(ctx context.Context, name, namespace string) (Pod, error) {
	args := m.Called(ctx, name, namespace)
	return args.Get(0).(Pod), args.Error(1)
}

func (m *MockK8sClient) GetServiceAccountIAMRole(ctx context.Context, namespace, saName string) (string, error) {
	args := m.Called(ctx, namespace, saName)
	return args.String(0), args.Error(1)
}

// Mock AWS Client
type MockAWSClient struct {
	mock.Mock
}

func (m *MockAWSClient) GetRolePolicies(ctx context.Context, roleName string) ([]types.Policy, error) {
	args := m.Called(ctx, roleName)
	return args.Get(0).([]types.Policy), args.Error(1)
}

func (m *MockAWSClient) GetPolicyPermissions(ctx context.Context, policyArn string) ([]types.PermissionDisplay, error) {
	args := m.Called(ctx, policyArn)
	return args.Get(0).([]types.PermissionDisplay), args.Error(1)
}

func TestAnalyzer_Analyze(t *testing.T) {
	tests := []struct {
		name           string
		opts           *options.Options
		setupMocks     func(*MockK8sClient, *MockAWSClient)
		expectedResult []types.PodPermissions
		expectedError  string
	}{
		{
			name: "successful pod analysis",
			opts: &options.Options{
				PodName:   "test-pod",
				Namespace: "default",
			},
			setupMocks: func(k8s *MockK8sClient, aws *MockAWSClient) {
				k8s.On("GetPod", mock.Anything, "test-pod", "default").Return(Pod{
					Spec: PodSpec{ServiceAccountName: "test-sa"},
				}, nil)
				k8s.On("GetServiceAccountIAMRole", mock.Anything, "default", "test-sa").Return("test-role", nil)
				aws.On("GetRolePolicies", mock.Anything, "test-role").Return([]types.Policy{
					{
						Name: "test-policy",
						Arn:  "arn:aws:iam::test-policy",
					},
				}, nil)
			},
			expectedResult: []types.PodPermissions{
				{
					PodName:        "test-pod",
					Namespace:      "default",
					ServiceAccount: "test-sa",
					IAMRole:        "test-role",
					Policies: []types.Policy{
						{
							Name: "test-policy",
							Arn:  "arn:aws:iam::test-policy",
						},
					},
				},
			},
		},
		{
			name: "pod not found",
			opts: &options.Options{
				PodName:   "nonexistent-pod",
				Namespace: "default",
			},
			setupMocks: func(k8s *MockK8sClient, aws *MockAWSClient) {
				k8s.On("GetPod", mock.Anything, "nonexistent-pod", "default").Return(Pod{}, assert.AnError)
			},
			expectedError: "failed to get pod nonexistent-pod",
		},
		{
			name: "namespace analysis",
			opts: &options.Options{
				Namespace: "default",
			},
			setupMocks: func(k8s *MockK8sClient, aws *MockAWSClient) {
				// Currently returns empty slice as per implementation
			},
			expectedResult: []types.PodPermissions{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockK8s := new(MockK8sClient)
			mockAWS := new(MockAWSClient)
			tt.setupMocks(mockK8s, mockAWS)

			analyzer := New(mockK8s, mockAWS)
			result, err := analyzer.Analyze(tt.opts)

			if tt.expectedError != "" {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedError)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expectedResult, result)
			}

			mockK8s.AssertExpectations(t)
			mockAWS.AssertExpectations(t)
		})
	}
}

func TestAnalyzePodPermissions(t *testing.T) {
	// TODO: Add tests for AnalyzePodPermissions function
	// This will require creating mock corev1.Pod objects and AWS client
	t.Skip("Implementation pending")
}

func TestAnalyzePod(t *testing.T) {
	k8s := &MockK8sClient{}
	aws := &MockAWSClient{}
	analyzer := New(k8s, aws)

	k8s.On("GetPod", mock.Anything, "test-pod", "default").Return(Pod{
		Spec: PodSpec{ServiceAccountName: "test-sa"},
	}, nil)

	k8s.On("GetServiceAccountIAMRole", mock.Anything, "default", "test-sa").Return("test-role", nil)

	aws.On("GetRolePolicies", mock.Anything, "test-role").Return([]types.Policy{
		{
			Name: "test-policy",
			Arn:  "arn:aws:iam::123456789012:policy/test-policy",
		},
	}, nil)

	aws.On("GetPolicyPermissions", mock.Anything, "arn:aws:iam::123456789012:policy/test-policy").Return([]types.PermissionDisplay{
		{
			Action:   "s3:GetObject",
			Resource: "arn:aws:s3:::my-bucket/*",
			Effect:   "Allow",
		},
	}, nil)

	result, err := analyzer.analyzePod(context.Background(), "test-pod", "default", &options.Options{})
	assert.NoError(t, err)
	assert.Len(t, result, 1)

	pod := result[0]
	assert.Equal(t, "test-pod", pod.PodName)
	assert.Equal(t, "default", pod.Namespace)
	assert.Equal(t, "test-sa", pod.ServiceAccount)
	assert.Equal(t, "test-role", pod.IAMRole)
	assert.Len(t, pod.Policies, 1)
	assert.Equal(t, "test-policy", pod.Policies[0].Name)
}
