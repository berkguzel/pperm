package aws

// Internal AWS types for policy parsing
type Statement struct {
	Effect   string   `json:"Effect"`
	Action   []string `json:"Action"`
	Resource []string `json:"Resource"`
}

type PolicyDocument struct {
	Statement []Statement `json:"Statement"`
}

type Permission struct {
	Action     string
	Resource   string
	Effect     string
	IsBroad    bool // For wildcard permissions
	IsHighRisk bool // For sensitive permissions
}
