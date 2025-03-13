package aws

// Internal AWS types for policy parsing
type Statement struct {
	Effect    string                            `json:"Effect"`
	Action    interface{}                       `json:"Action"`              // Can be string or []string
	Resource  interface{}                       `json:"Resource"`            // Can be string or []string
	Condition map[string]map[string]interface{} `json:"Condition,omitempty"` // For IAM policy conditions
	Principal interface{}                       `json:"Principal,omitempty"`
	Sid       string                            `json:"Sid,omitempty"`
}

type PolicyDocument struct {
	Version   string      `json:"Version"`
	Statement []Statement `json:"Statement"`
}

type Permission struct {
	Action       string
	Resource     string
	Effect       string
	IsBroad      bool // For wildcard permissions
	IsHighRisk   bool // For sensitive permissions
	HasCondition bool // Track if permission has conditions
}

// Add this helper function to handle both string and array cases
func getActions(action interface{}) []string {
	switch v := action.(type) {
	case string:
		return []string{v}
	case []interface{}:
		actions := make([]string, len(v))
		for i, a := range v {
			if s, ok := a.(string); ok {
				actions[i] = s
			}
		}
		return actions
	}
	return nil
}

// Add this helper function for resources
func getResources(resource interface{}) []string {
	switch v := resource.(type) {
	case string:
		return []string{v}
	case []interface{}:
		resources := make([]string, len(v))
		for i, r := range v {
			if s, ok := r.(string); ok {
				resources[i] = s
			}
		}
		return resources
	}
	return nil
}
