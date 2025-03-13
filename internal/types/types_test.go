package types

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestStatementInfo(t *testing.T) {
	statement := StatementInfo{
		Effect:    "Allow",
		Actions:   []string{"s3:GetObject", "s3:PutObject"},
		Resources: []string{"arn:aws:s3:::my-bucket/*"},
	}

	assert.Equal(t, "Allow", statement.Effect)
	assert.Len(t, statement.Actions, 2)
	assert.Contains(t, statement.Actions, "s3:GetObject")
	assert.Contains(t, statement.Actions, "s3:PutObject")
	assert.Equal(t, []string{"arn:aws:s3:::my-bucket/*"}, statement.Resources)
}

func TestWarning(t *testing.T) {
	warning := Warning{
		Level:       "High",
		Description: "Overly permissive S3 access",
		Action:      "Review S3 bucket permissions",
	}

	assert.Equal(t, "High", warning.Level)
	assert.Equal(t, "Overly permissive S3 access", warning.Description)
	assert.Equal(t, "Review S3 bucket permissions", warning.Action)
}
