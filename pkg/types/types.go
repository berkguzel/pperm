package types

type PermissionDisplay struct {
	Action     string
	Resource   string
	Effect     string
	IsBroad    bool
	IsHighRisk bool
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
