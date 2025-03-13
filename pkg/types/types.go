package types

import (
	"fmt"
)

type Permission struct {
	Action     string
	Resource   string
	Effect     string
	IsBroad    bool
	IsHighRisk bool
}

type PermissionDisplay struct {
	Action       string
	Resource     string
	Effect       string
	IsBroad      bool
	IsHighRisk   bool
	HasCondition bool
}

type Policy struct {
	Name        string
	Arn         string
	Permissions []PermissionDisplay
}

type PodPermissions struct {
	PodName        string
	Namespace      string
	ServiceAccount string
	IAMRole        string
	Policies       []Policy
}

type StatementInfo struct {
	Effect    string
	Actions   []string
	Resources []string
}

func (p PermissionDisplay) String() string {
	return fmt.Sprintf("%s %s on %s (Broad: %v, High Risk: %v, Has Condition: %v)",
		p.Effect, p.Action, p.Resource, p.IsBroad, p.IsHighRisk, p.HasCondition)
}

func (p Policy) String() string {
	return fmt.Sprintf("Policy: %s (%s) with %d permissions",
		p.Name, p.Arn, len(p.Permissions))
}

func (p PodPermissions) String() string {
	return fmt.Sprintf("Pod: %s in namespace %s using service account %s with IAM role %s (%d policies)",
		p.PodName, p.Namespace, p.ServiceAccount, p.IAMRole, len(p.Policies))
}
