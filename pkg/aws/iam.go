package aws

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/berkguzel/pperm/pkg/types"
)

// BatchSize determines how many policies to process in parallel
const BatchSize = 10

// Cache configuration
const (
	cacheExpiration       = 1 * time.Minute
	maxCacheSize          = 1000
	cacheSaveInterval     = 5 * time.Minute
	maxConcurrentAPICalls = 8
)

// Add timeout constants
const (
	listPoliciesTimeout  = 10 * time.Second
	getPolicyTimeout     = 10 * time.Second
	resultCollectTimeout = 15 * time.Second
	apiOperationTimeout  = 5 * time.Second
)

// Add at the top of the file after imports
const cacheFileName = ".pperm_cache.json"

// Remove persistent cache
type cacheEntry struct {
	permissions []types.PermissionDisplay
	timestamp   time.Time
	versionId   string
	document    PolicyDocument
	lastAccess  time.Time
}

// Cache with TTL and LRU eviction
type Cache struct {
	sync.RWMutex
	items   map[string]cacheEntry
	size    int
	hits    int64
	misses  int64
	evicted int64
}

var policyCache = &Cache{
	items: make(map[string]cacheEntry),
}

func (c *Cache) Get(key string) (cacheEntry, bool) {
	c.RLock()
	defer c.RUnlock()

	entry, exists := c.items[key]
	if !exists {
		atomic.AddInt64(&c.misses, 1)
		return cacheEntry{}, false
	}

	// Check if entry has expired
	if time.Since(entry.timestamp) > cacheExpiration {
		atomic.AddInt64(&c.evicted, 1)
		delete(c.items, key)
		c.size--
		return cacheEntry{}, false
	}

	// Validate the entry
	valid := true
	for _, stmt := range entry.document.Statement {
		hasCondition := stmt.Condition != nil && len(stmt.Condition) > 0
		for _, perm := range entry.permissions {
			if (hasCondition && !perm.HasCondition) || (!hasCondition && perm.HasCondition) {
				valid = false
				break
			}
		}
		if !valid {
			break
		}
	}

	if !valid {
		delete(c.items, key)
		c.size--
		return cacheEntry{}, false
	}

	// Update last access time
	entry.lastAccess = time.Now()
	c.items[key] = entry
	atomic.AddInt64(&c.hits, 1)

	return entry, true
}

func (c *Cache) Set(key string, entry cacheEntry) {
	c.Lock()
	defer c.Unlock()

	// Validate the entry before caching
	valid := true
	for _, stmt := range entry.document.Statement {
		hasCondition := stmt.Condition != nil && len(stmt.Condition) > 0
		for _, perm := range entry.permissions {
			if (hasCondition && !perm.HasCondition) || (!hasCondition && perm.HasCondition) {
				valid = false
				break
			}
		}
		if !valid {
			break
		}
	}

	if !valid {
		return
	}

	// If cache is full, remove least recently used entries
	if c.size >= maxCacheSize && c.items[key].timestamp.IsZero() {
		lru := time.Now()
		var lruKey string
		for k, v := range c.items {
			if v.lastAccess.Before(lru) {
				lru = v.lastAccess
				lruKey = k
			}
		}
		delete(c.items, lruKey)
		c.size--
		atomic.AddInt64(&c.evicted, 1)
	}

	entry.lastAccess = time.Now()
	c.items[key] = entry
	if c.items[key].timestamp.IsZero() {
		c.size++
	}
}

func (c *Cache) GetMetrics() map[string]int64 {
	return map[string]int64{
		"size":    int64(c.size),
		"hits":    atomic.LoadInt64(&c.hits),
		"misses":  atomic.LoadInt64(&c.misses),
		"evicted": atomic.LoadInt64(&c.evicted),
	}
}

func convertPolicyDocument(name, arn string, perms []types.PermissionDisplay) types.Policy {
	return types.Policy{
		Name:        name,
		Arn:         arn,
		Permissions: perms,
	}
}

// WorkerPool manages a pool of workers for parallel policy processing
type WorkerPool struct {
	numWorkers int
	jobs       chan policyJob
	results    chan policyResult
	errors     chan error
}

type policyJob struct {
	policy iamtypes.AttachedPolicy
}

type policyResult struct {
	policy types.Policy
	err    error
}

func newWorkerPool(numWorkers int) *WorkerPool {
	return &WorkerPool{
		numWorkers: numWorkers,
		jobs:       make(chan policyJob, numWorkers),
		results:    make(chan policyResult, numWorkers),
		errors:     make(chan error, numWorkers),
	}
}

func (wp *WorkerPool) start(ctx context.Context, client *Client) {
	var wg sync.WaitGroup
	for i := 0; i < wp.numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for job := range wp.jobs {
				select {
				case <-ctx.Done():
					return
				default:
					perms, err := client.GetPolicyPermissions(ctx, aws.ToString(job.policy.PolicyArn))
					if err != nil {
						wp.errors <- fmt.Errorf("error getting permissions for policy %s: %v",
							aws.ToString(job.policy.PolicyArn), err)
						continue
					}
					wp.results <- policyResult{
						policy: types.Policy{
							Name:        aws.ToString(job.policy.PolicyName),
							Arn:         aws.ToString(job.policy.PolicyArn),
							Permissions: perms,
						},
						err: nil,
					}
				}
			}
		}()
	}

	go func() {
		wg.Wait()
		close(wp.results)
		close(wp.errors)
	}()
}

func (c *Client) GetRolePolicies(ctx context.Context, roleArn string) ([]types.Policy, error) {
	roleName := getRoleNameFromARN(roleArn)
	var policies []types.Policy

	result, err := c.iamClient.ListAttachedRolePolicies(ctx, &iam.ListAttachedRolePoliciesInput{
		RoleName: &roleName,
	})

	if err != nil {
		return nil, fmt.Errorf("failed to list attached role policies: %v", err)
	}

	var wg sync.WaitGroup
	var mu sync.Mutex
	errorChan := make(chan error, len(result.AttachedPolicies))

	// DISABLE CACHE - Always fetch fresh data
	for _, policy := range result.AttachedPolicies {
		wg.Add(1)
		go func(p iamtypes.AttachedPolicy) {
			defer wg.Done()

			policyArn := aws.ToString(p.PolicyArn)
			policyName := aws.ToString(p.PolicyName)

			perms, err := c.GetPolicyPermissions(ctx, policyArn)
			if err != nil {
				errorChan <- fmt.Errorf("failed to get policy permissions for %s: %v", policyArn, err)
				return
			}

			mu.Lock()
			policies = append(policies, types.Policy{
				Name:        policyName,
				Arn:         policyArn,
				Permissions: perms,
			})
			mu.Unlock()
		}(policy)
	}

	go func() {
		wg.Wait()
		close(errorChan)
	}()

	var errs []error
	for err := range errorChan {
		errs = append(errs, err)
	}

	if len(errs) > 0 {
		return policies, fmt.Errorf("errors getting policy permissions: %v", errs)
	}

	return policies, nil
}

// Fix the Metrics struct and methods
type Metrics struct {
	sync.RWMutex
	apiLatencies   map[string][]time.Duration
	cacheHitRate   float64
	totalAPICalls  int64
	totalCacheHits int64
	lastCalculated time.Time
	lastMetrics    map[string]interface{}
}

var metrics = &Metrics{
	apiLatencies: make(map[string][]time.Duration),
}

func (m *Metrics) recordAPILatency(operation string, duration time.Duration) {
	m.Lock()
	defer m.Unlock()

	m.apiLatencies[operation] = append(m.apiLatencies[operation], duration)
	atomic.AddInt64(&m.totalAPICalls, 1)
}

func (m *Metrics) recordCacheHit() {
	atomic.AddInt64(&m.totalCacheHits, 1)
}

func (m *Metrics) GetMetrics() map[string]interface{} {
	m.Lock()
	defer m.Unlock()

	// Only recalculate metrics every minute
	if time.Since(m.lastCalculated) < time.Minute {
		return m.lastMetrics
	}

	metrics := make(map[string]interface{})

	// Calculate average latencies
	for op, latencies := range m.apiLatencies {
		var total time.Duration
		for _, d := range latencies {
			total += d
		}
		if len(latencies) > 0 {
			metrics[op+"_avg_latency"] = total / time.Duration(len(latencies))
		}
	}

	// Calculate cache hit rate
	totalOps := atomic.LoadInt64(&m.totalAPICalls)
	hits := atomic.LoadInt64(&m.totalCacheHits)
	if totalOps > 0 {
		m.cacheHitRate = float64(hits) / float64(totalOps)
	}

	metrics["cache_hit_rate"] = m.cacheHitRate
	metrics["total_api_calls"] = totalOps
	metrics["total_cache_hits"] = hits

	m.lastCalculated = time.Now()
	m.lastMetrics = metrics
	return metrics
}

// Fix the GetPolicyPermissions method
func (c *Client) GetPolicyPermissions(ctx context.Context, policyArn string) ([]types.PermissionDisplay, error) {
	start := time.Now()
	defer func() {
		metrics.recordAPILatency("GetPolicyPermissions", time.Since(start))
	}()

	// DISABLE CACHE COMPLETELY - Always fetch fresh data

	quickCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	policy, err := c.iamClient.GetPolicy(quickCtx, &iam.GetPolicyInput{
		PolicyArn: &policyArn,
	})

	if err != nil {
		return nil, fmt.Errorf("failed to get policy: %v", err)
	}

	versionCtx, versionCancel := context.WithTimeout(ctx, 5*time.Second)
	defer versionCancel()

	version, err := c.iamClient.GetPolicyVersion(versionCtx, &iam.GetPolicyVersionInput{
		PolicyArn: &policyArn,
		VersionId: policy.Policy.DefaultVersionId,
	})

	if err != nil {
		return nil, fmt.Errorf("failed to get policy version: %v", err)
	}

	decodedDoc, err := url.QueryUnescape(*version.PolicyVersion.Document)
	if err != nil {
		return nil, fmt.Errorf("failed to decode policy document: %v", err)
	}

	var doc PolicyDocument
	if err := json.Unmarshal([]byte(decodedDoc), &doc); err != nil {
		return nil, fmt.Errorf("failed to parse policy document: %v", err)
	}

	perms := formatPermissions(doc.Statement)

	return perms, nil
}

func formatPermissions(statements []Statement) []types.PermissionDisplay {
	var permissions []types.PermissionDisplay

	for _, stmt := range statements {
		actions := getActions(stmt.Action)
		resources := getResources(stmt.Resource)

		// Explicit condition check
		hasCondition := stmt.Condition != nil && len(stmt.Condition) > 0

		for _, action := range actions {
			for _, resource := range resources {
				isBroad := strings.Contains(action, "*") || strings.Contains(resource, "*")
				isHighRisk := isHighRiskService(action)

				perm := types.PermissionDisplay{
					Action:       action,
					Resource:     resource,
					Effect:       stmt.Effect,
					IsBroad:      isBroad,
					IsHighRisk:   isHighRisk,
					HasCondition: hasCondition,
				}

				permissions = append(permissions, perm)
			}
		}
	}

	return permissions
}
