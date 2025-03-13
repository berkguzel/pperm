package aws

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewClient(t *testing.T) {
	// Save original env vars
	originalRegion := os.Getenv("AWS_REGION")
	originalDefaultRegion := os.Getenv("AWS_DEFAULT_REGION")
	originalCluster := os.Getenv("CLUSTER_NAME")
	defer func() {
		os.Setenv("AWS_REGION", originalRegion)
		os.Setenv("AWS_DEFAULT_REGION", originalDefaultRegion)
		os.Setenv("CLUSTER_NAME", originalCluster)
	}()

	tests := []struct {
		name          string
		setupEnv      func()
		wantErr       bool
		errorContains string
	}{
		{
			name: "AWS_REGION set",
			setupEnv: func() {
				os.Setenv("AWS_REGION", "us-west-2")
				os.Setenv("AWS_DEFAULT_REGION", "")
				os.Setenv("CLUSTER_NAME", "")
			},
			wantErr: false,
		},
		{
			name: "AWS_DEFAULT_REGION set",
			setupEnv: func() {
				os.Setenv("AWS_REGION", "")
				os.Setenv("AWS_DEFAULT_REGION", "us-east-1")
				os.Setenv("CLUSTER_NAME", "")
			},
			wantErr: false,
		},
		{
			name: "cluster name with region",
			setupEnv: func() {
				os.Setenv("AWS_REGION", "")
				os.Setenv("AWS_DEFAULT_REGION", "")
				os.Setenv("CLUSTER_NAME", "us-west-2.my-cluster")
			},
			wantErr: false,
		},
		{
			name: "no region configured",
			setupEnv: func() {
				os.Setenv("AWS_REGION", "")
				os.Setenv("AWS_DEFAULT_REGION", "")
				os.Setenv("CLUSTER_NAME", "")
			},
			wantErr:       true,
			errorContains: "no AWS region specified",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.setupEnv()
			client, err := NewClient()
			if tt.wantErr {
				assert.Error(t, err)
				if tt.errorContains != "" {
					assert.Contains(t, err.Error(), tt.errorContains)
				}
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, client)
				assert.NotNil(t, client.iamClient)
			}
		})
	}
}
