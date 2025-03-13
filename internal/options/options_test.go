package options

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewOptions(t *testing.T) {
	// Save original env and restore after test
	originalKubeconfig := os.Getenv("KUBECONFIG")
	defer os.Setenv("KUBECONFIG", originalKubeconfig)

	t.Run("uses KUBECONFIG env var", func(t *testing.T) {
		testPath := "/test/config"
		os.Setenv("KUBECONFIG", testPath)
		opts := NewOptions()
		assert.Equal(t, testPath, opts.KubeConfig)
	})

	t.Run("falls back to default path", func(t *testing.T) {
		os.Setenv("KUBECONFIG", "")
		opts := NewOptions()
		assert.Contains(t, opts.KubeConfig, ".kube/config")
	})
}

func TestOptions_Parse(t *testing.T) {
	// Save original args and restore after test
	originalArgs := os.Args
	defer func() { os.Args = originalArgs }()

	// Create a temporary kubeconfig file
	tmpKubeconfig, err := os.CreateTemp("", "kubeconfig")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpKubeconfig.Name())

	// Set KUBECONFIG to temp file
	originalKubeconfig := os.Getenv("KUBECONFIG")
	os.Setenv("KUBECONFIG", tmpKubeconfig.Name())
	defer os.Setenv("KUBECONFIG", originalKubeconfig)

	tests := []struct {
		name     string
		args     []string
		expected Options
		wantErr  bool
	}{
		{
			name: "help flag",
			args: []string{"pperm", "--help"},
			expected: Options{
				Help:      true,
				Namespace: "default", // Namespace will always be "default" when no config exists
			},
		},
		{
			name: "pod name only",
			args: []string{"pperm", "my-pod"},
			expected: Options{
				PodName:   "my-pod",
				Namespace: "default", // Namespace will always be "default" when no config exists
			},
		},
		{
			name: "all flags",
			args: []string{"pperm", "my-pod", "-n", "test-ns", "-i", "-r", "--permissions"},
			expected: Options{
				PodName:       "my-pod",
				Namespace:     "test-ns",
				InspectPolicy: true,
				RiskOnly:      true,
				ShowPerms:     true,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			os.Args = tt.args
			opts := NewOptions()
			err := opts.Parse()

			if tt.wantErr {
				assert.Error(t, err)
				return
			}

			assert.NoError(t, err)
			assert.Equal(t, tt.expected.Help, opts.Help)
			assert.Equal(t, tt.expected.PodName, opts.PodName)
			assert.Equal(t, tt.expected.Namespace, opts.Namespace)
			assert.Equal(t, tt.expected.InspectPolicy, opts.InspectPolicy)
			assert.Equal(t, tt.expected.RiskOnly, opts.RiskOnly)
			assert.Equal(t, tt.expected.ShowPerms, opts.ShowPerms)
		})
	}
}
