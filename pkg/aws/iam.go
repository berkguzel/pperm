package aws

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/berkguzel/pperm/pkg/types"
)

var (
	// Cache for policy permissions to avoid repeated API calls
	policyCache     = make(map[string]cacheEntry)
	cacheMutex      sync.RWMutex
	cacheExpiration = 24 * time.Hour // Cache entries expire after 24 hours
)

type cacheEntry struct {
	permissions []types.PermissionDisplay
	timestamp   time.Time
	versionId   string
	document    PolicyDocument // Cache the parsed document to avoid repeated parsing
}

func convertPolicyDocument(name, arn string, perms []types.PermissionDisplay) types.Policy {
	return types.Policy{
		Name:        name,
		Arn:         arn,
		Permissions: perms,
	}
}

func (c *Client) GetRolePolicies(ctx context.Context, roleArn string) ([]types.Policy, error) {
	// Add timeout to context
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	roleName := getRoleNameFromARN(roleArn)
	var policies []types.Policy

	// Get list of policies with retries and exponential backoff
	var result *iam.ListAttachedRolePoliciesOutput
	var err error
	backoff := 100 * time.Millisecond
	maxBackoff := 2 * time.Second
	maxRetries := 3

	for retries := 0; retries < maxRetries; retries++ {
		if retries > 0 {
			if backoff < maxBackoff {
				backoff *= 2
			}
			time.Sleep(backoff)
		}

		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("operation timed out while listing policies for role %s", roleArn)
		default:
			result, err = c.iamClient.ListAttachedRolePolicies(ctx, &iam.ListAttachedRolePoliciesInput{
				RoleName: &roleName,
			})
			if err == nil {
				break
			}
		}
	}

	if err != nil {
		return nil, fmt.Errorf("failed to list policies after %d retries: %v", maxRetries, err)
	}

	if len(result.AttachedPolicies) == 0 {
		return policies, nil
	}

	// Create channels for results and errors
	type policyResult struct {
		policy types.Policy
		err    error
	}
	resultChan := make(chan policyResult, len(result.AttachedPolicies))
	errorChan := make(chan error, len(result.AttachedPolicies))
	doneChan := make(chan struct{})

	// Create a wait group to ensure all goroutines complete
	var wg sync.WaitGroup

	// Start a goroutine to collect results
	go func() {
		for res := range resultChan {
			if res.err != nil {
				errorChan <- res.err
			} else {
				policies = append(policies, res.policy)
			}
		}
		close(doneChan)
	}()

	// Use a worker pool to limit concurrent API calls
	const maxWorkers = 4
	semaphore := make(chan struct{}, maxWorkers)

	// Fetch permissions for each policy in parallel
	for _, policy := range result.AttachedPolicies {
		wg.Add(1)
		policyName := *policy.PolicyName
		policyArn := *policy.PolicyArn

		go func() {
			defer wg.Done()
			semaphore <- struct{}{}        // Acquire semaphore
			defer func() { <-semaphore }() // Release semaphore

			perms, err := c.GetPolicyPermissions(ctx, policyArn)
			if err != nil {
				resultChan <- policyResult{err: fmt.Errorf("error getting permissions for policy %s: %v", policyArn, err)}
				return
			}

			resultChan <- policyResult{
				policy: types.Policy{
					Name:        policyName,
					Arn:         policyArn,
					Permissions: perms,
				},
				err: nil,
			}
		}()
	}

	// Wait for all goroutines to complete and close channels
	go func() {
		wg.Wait()
		close(resultChan)
		close(errorChan)
	}()

	// Wait for either completion or context cancellation
	select {
	case <-ctx.Done():
		return policies, fmt.Errorf("operation timed out")
	case <-doneChan:
	}

	// Check for any errors
	select {
	case err := <-errorChan:
		if err != nil {
			return policies, fmt.Errorf("error fetching policies: %v", err)
		}
	default:
	}

	return policies, nil
}

// Only call this when permissions are needed
func (c *Client) GetPolicyPermissions(ctx context.Context, policyArn string) ([]types.PermissionDisplay, error) {
	// Check cache first before making any API calls
	cacheMutex.RLock()
	if entry, ok := policyCache[policyArn]; ok && time.Since(entry.timestamp) < cacheExpiration {
		cacheMutex.RUnlock()
		return entry.permissions, nil
	}
	cacheMutex.RUnlock()

	// Create channels for parallel fetching
	type policyResult struct {
		policy  *iam.GetPolicyOutput
		version *iam.GetPolicyVersionOutput
		err     error
	}
	resultChan := make(chan policyResult, 2)

	// Fetch policy and version in parallel
	var wg sync.WaitGroup
	wg.Add(2)

	// Fetch policy
	go func() {
		defer wg.Done()
		policy, err := c.iamClient.GetPolicy(ctx, &iam.GetPolicyInput{
			PolicyArn: &policyArn,
		})
		if err != nil {
			resultChan <- policyResult{err: fmt.Errorf("failed to get policy: %v", err)}
			return
		}
		resultChan <- policyResult{policy: policy}
	}()

	// Fetch latest version (we'll update versionId if needed)
	go func() {
		defer wg.Done()
		version, err := c.iamClient.GetPolicyVersion(ctx, &iam.GetPolicyVersionInput{
			PolicyArn: &policyArn,
			VersionId: aws.String("v1"), // We'll update this if needed
		})
		if err != nil {
			resultChan <- policyResult{err: fmt.Errorf("failed to get policy version: %v", err)}
			return
		}
		resultChan <- policyResult{version: version}
	}()

	// Wait for both goroutines to complete
	go func() {
		wg.Wait()
		close(resultChan)
	}()

	// Collect results
	var policy *iam.GetPolicyOutput
	var version *iam.GetPolicyVersionOutput
	for result := range resultChan {
		if result.err != nil {
			return nil, result.err
		}
		if result.policy != nil {
			policy = result.policy
		}
		if result.version != nil {
			version = result.version
		}
	}

	// Parse policy document
	decodedDoc, err := url.QueryUnescape(*version.PolicyVersion.Document)
	if err != nil {
		return nil, fmt.Errorf("failed to decode policy document: %v", err)
	}

	var doc PolicyDocument
	if err := json.Unmarshal([]byte(decodedDoc), &doc); err != nil {
		return nil, fmt.Errorf("failed to parse policy document: %v", err)
	}

	perms := formatPermissions(doc.Statement)

	// Cache the result with version
	cacheMutex.Lock()
	policyCache[policyArn] = cacheEntry{
		permissions: perms,
		timestamp:   time.Now(),
		versionId:   *policy.Policy.DefaultVersionId,
		document:    doc,
	}
	cacheMutex.Unlock()

	return perms, nil
}

func formatPermissions(statements []Statement) []types.PermissionDisplay {
	var permissions []types.PermissionDisplay

	for _, stmt := range statements {
		actions := getActions(stmt.Action)
		resources := getResources(stmt.Resource)
		hasCondition := len(stmt.Condition) > 0

		for _, action := range actions {
			for _, resource := range resources {
				isBroad := strings.Contains(action, "*") || strings.Contains(resource, "*")
				isHighRisk := isHighRiskService(action)

				permissions = append(permissions, types.PermissionDisplay{
					Action:       action,
					Resource:     resource,
					Effect:       stmt.Effect,
					IsBroad:      isBroad,
					IsHighRisk:   isHighRisk,
					HasCondition: hasCondition,
				})
			}
		}
	}

	return permissions
}
