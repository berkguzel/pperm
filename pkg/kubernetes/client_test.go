package kubernetes

import (
	"context"
	"fmt"
	"testing"

	"github.com/berkguzel/pperm/pkg/analyzer"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// mockKubernetesClient implements KubernetesClient for testing
type mockKubernetesClient struct {
	mock.Mock
}

func (m *mockKubernetesClient) GetPod(ctx context.Context, name, namespace string) (analyzer.Pod, error) {
	args := m.Called(ctx, name, namespace)
	return args.Get(0).(analyzer.Pod), args.Error(1)
}

func (m *mockKubernetesClient) GetServiceAccountIAMRole(ctx context.Context, namespace, name string) (string, error) {
	args := m.Called(ctx, namespace, name)
	return args.String(0), args.Error(1)
}

func TestClient_GetPod(t *testing.T) {
	tests := []struct {
		name          string
		podName       string
		namespace     string
		mockPod       analyzer.Pod
		mockError     error
		expectedError string
	}{
		{
			name:      "successful pod retrieval",
			podName:   "test-pod",
			namespace: "default",
			mockPod: analyzer.Pod{
				Spec: analyzer.PodSpec{
					ServiceAccountName: "test-sa",
				},
			},
			mockError: nil,
		},
		{
			name:          "pod not found",
			podName:       "nonexistent-pod",
			namespace:     "default",
			mockPod:       analyzer.Pod{},
			mockError:     fmt.Errorf("error getting pod"),
			expectedError: "error getting pod",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockClient := &mockKubernetesClient{}
			mockClient.On("GetPod", mock.Anything, tt.podName, tt.namespace).Return(tt.mockPod, tt.mockError)

			result, err := mockClient.GetPod(context.Background(), tt.podName, tt.namespace)

			if tt.expectedError != "" {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedError)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.mockPod.Spec.ServiceAccountName, result.Spec.ServiceAccountName)
			}

			mockClient.AssertExpectations(t)
		})
	}
}

func TestClient_GetServiceAccountIAMRole(t *testing.T) {
	tests := []struct {
		name          string
		namespace     string
		saName        string
		mockRole      string
		mockError     error
		expectedError string
	}{
		{
			name:      "successful role retrieval",
			namespace: "default",
			saName:    "test-sa",
			mockRole:  "arn:aws:iam::123456789012:role/test-role",
			mockError: nil,
		},
		{
			name:          "service account not found",
			namespace:     "default",
			saName:        "nonexistent-sa",
			mockRole:      "",
			mockError:     fmt.Errorf("no IAM role annotation found on service account"),
			expectedError: "no IAM role annotation found on service account",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockClient := &mockKubernetesClient{}
			mockClient.On("GetServiceAccountIAMRole", mock.Anything, tt.namespace, tt.saName).Return(tt.mockRole, tt.mockError)

			role, err := mockClient.GetServiceAccountIAMRole(context.Background(), tt.namespace, tt.saName)

			if tt.expectedError != "" {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedError)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.mockRole, role)
			}

			mockClient.AssertExpectations(t)
		})
	}
}
