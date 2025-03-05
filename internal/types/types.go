package types


type StatementInfo struct {
	Effect    string
	Actions   []string
	Resources []string
}

type Warning struct {
	Level       string // High, Medium, Low
	Description string
	Action      string
}

type Client interface {
    // Add any common methods here
}