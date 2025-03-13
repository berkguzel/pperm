package main

import (
	"testing"

	"github.com/berkguzel/pperm/internal/options"
	"github.com/stretchr/testify/assert"
)

func TestRun(t *testing.T) {
	tests := []struct {
		name    string
		opts    *options.Options
		wantErr bool
	}{
		{
			name: "missing pod name",
			opts: &options.Options{
				PodName: "",
			},
			wantErr: true,
		},
		{
			name: "valid options with empty namespace",
			opts: &options.Options{
				PodName: "test-pod",
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := run(tt.opts)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				t.Skip("Skipping non-error case as it requires AWS configuration")
			}
		})
	}
}
