package aws

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
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
	listPoliciesTimeout  = 2 * time.Second
	getPolicyTimeout     = 1 * time.Second
	resultCollectTimeout = 3 * time.Second
	apiOperationTimeout  = 750 * time.Millisecond
)

// Add at the top of the file after imports
const cacheFileName = ".pperm_cache.json"

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
	items    map[string]cacheEntry
	size     int
	hits     int64
	misses   int64
	evicted  int64
	lastSave time.Time
}

var policyCache = &Cache{
	items: make(map[string]cacheEntry),
}

type persistentCache struct {
	Entries  map[string]cacheEntry `json:"entries"`
	LastSave time.Time             `json:"last_save"`
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

	// Update last access time
	entry.lastAccess = time.Now()
	c.items[key] = entry
	atomic.AddInt64(&c.hits, 1)

	return entry, true
}

func (c *Cache) Set(key string, entry cacheEntry) {
	c.Lock()
	defer c.Unlock()

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
	defer func() {
		if time.Since(policyCache.lastSave) >= cacheSaveInterval {
			go saveCache()
		}
	}()

	roleName := getRoleNameFromARN(roleArn)
	var policies []types.Policy

	listCtx, cancel := context.WithTimeout(ctx, listPoliciesTimeout)
	defer cancel()

	result, err := c.iamClient.ListAttachedRolePolicies(listCtx, &iam.ListAttachedRolePoliciesInput{
		RoleName: &roleName,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to list policies: %v", err)
	}

	if len(result.AttachedPolicies) == 0 {
		return policies, nil
	}

	sem := make(chan struct{}, maxConcurrentAPICalls)
	var wg sync.WaitGroup
	resultChan := make(chan types.Policy, len(result.AttachedPolicies))
	errorChan := make(chan error, len(result.AttachedPolicies))

	cachedPolicies := make(map[string]types.Policy)
	for _, policy := range result.AttachedPolicies {
		if entry, ok := policyCache.Get(aws.ToString(policy.PolicyArn)); ok {
			cachedPolicies[aws.ToString(policy.PolicyArn)] = types.Policy{
				Name:        aws.ToString(policy.PolicyName),
				Arn:         aws.ToString(policy.PolicyArn),
				Permissions: entry.permissions,
			}
		}
	}

	for _, policy := range result.AttachedPolicies {
		policyArn := aws.ToString(policy.PolicyArn)
		if _, ok := cachedPolicies[policyArn]; ok {
			continue
		}

		wg.Add(1)
		go func(p iamtypes.AttachedPolicy) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			perms, err := c.GetPolicyPermissions(ctx, aws.ToString(p.PolicyArn))
			if err != nil {
				errorChan <- err
				return
			}
			resultChan <- types.Policy{
				Name:        aws.ToString(p.PolicyName),
				Arn:         aws.ToString(p.PolicyArn),
				Permissions: perms,
			}
		}(policy)
	}

	go func() {
		wg.Wait()
		close(resultChan)
		close(errorChan)
	}()

	for _, policy := range cachedPolicies {
		policies = append(policies, policy)
	}

	timeout := time.After(resultCollectTimeout)
	var errs []error

	remainingPolicies := len(result.AttachedPolicies) - len(cachedPolicies)
	for i := 0; i < remainingPolicies; i++ {
		select {
		case policy := <-resultChan:
			policies = append(policies, policy)
		case err := <-errorChan:
			errs = append(errs, err)
		case <-timeout:
			if len(policies) > 0 {
				return policies, nil
			}
			return nil, fmt.Errorf("timeout while processing policies")
		case <-ctx.Done():
			return policies, nil
		}
	}

	if len(errs) > 0 && len(policies) == 0 {
		return nil, fmt.Errorf("failed to get any policies: %v", errs[0])
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

	quickCtx, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
	defer cancel()

	policy, err := c.iamClient.GetPolicy(quickCtx, &iam.GetPolicyInput{
		PolicyArn: &policyArn,
	})

	if err == nil {
		if entry, ok := policyCache.Get(policyArn); ok {
			if entry.versionId == *policy.Policy.DefaultVersionId {
				metrics.recordCacheHit()
				return entry.permissions, nil
			}
		}
	} else {
		if entry, ok := policyCache.Get(policyArn); ok {
			metrics.recordCacheHit()
			return entry.permissions, nil
		}
	}

	ctx, cancel = context.WithTimeout(ctx, getPolicyTimeout)
	defer cancel()

	var version *iam.GetPolicyVersionOutput
	if policy != nil {
		version, err = c.iamClient.GetPolicyVersion(ctx, &iam.GetPolicyVersionInput{
			PolicyArn: &policyArn,
			VersionId: policy.Policy.DefaultVersionId,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to get policy version: %v", err)
		}
	} else {
		policyChan := make(chan *iam.GetPolicyOutput, 1)
		versionChan := make(chan *iam.GetPolicyVersionOutput, 1)
		errChan := make(chan error, 2)

		go func() {
			policy, err := c.iamClient.GetPolicy(ctx, &iam.GetPolicyInput{
				PolicyArn: &policyArn,
			})
			if err != nil {
				errChan <- fmt.Errorf("failed to get policy: %v", err)
				return
			}
			policyChan <- policy
		}()

		go func() {
			version, err := c.iamClient.GetPolicyVersion(ctx, &iam.GetPolicyVersionInput{
				PolicyArn: &policyArn,
				VersionId: aws.String("v1"),
			})
			if err != nil {
				errChan <- fmt.Errorf("failed to get policy version: %v", err)
				return
			}
			versionChan <- version
		}()

		timeout := time.After(apiOperationTimeout)

		for i := 0; i < 2; i++ {
			select {
			case p := <-policyChan:
				policy = p
			case v := <-versionChan:
				version = v
			case err := <-errChan:
				if strings.Contains(err.Error(), "v1") && policy != nil {
					version, err = c.iamClient.GetPolicyVersion(ctx, &iam.GetPolicyVersionInput{
						PolicyArn: &policyArn,
						VersionId: policy.Policy.DefaultVersionId,
					})
					if err != nil {
						return nil, fmt.Errorf("failed to get policy version: %v", err)
					}
				} else {
					return nil, err
				}
			case <-timeout:
				return nil, fmt.Errorf("timeout getting policy data")
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
	}

	if policy == nil || version == nil {
		return nil, fmt.Errorf("failed to get complete policy data")
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

	policyCache.Set(policyArn, cacheEntry{
		permissions: perms,
		timestamp:   time.Now(),
		versionId:   *policy.Policy.DefaultVersionId,
		document:    doc,
	})

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

// Add after Cache struct definition
func loadCache() {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return
	}

	cacheFile := filepath.Join(homeDir, cacheFileName)
	data, err := os.ReadFile(cacheFile)
	if err != nil {
		return
	}

	var pc persistentCache
	if err := json.Unmarshal(data, &pc); err != nil {
		return
	}

	// Only load non-expired entries
	now := time.Now()
	for k, v := range pc.Entries {
		if now.Sub(v.timestamp) < cacheExpiration {
			policyCache.Set(k, v)
		}
	}
}

func saveCache() {
	policyCache.Lock()
	defer policyCache.Unlock()

	// Only save if enough time has passed since last save
	if time.Since(policyCache.lastSave) < cacheSaveInterval {
		return
	}

	homeDir, err := os.UserHomeDir()
	if err != nil {
		return
	}

	cacheFile := filepath.Join(homeDir, cacheFileName)

	// Only save non-expired entries
	validEntries := make(map[string]cacheEntry)
	now := time.Now()
	for k, v := range policyCache.items {
		if now.Sub(v.timestamp) < cacheExpiration {
			validEntries[k] = v
		}
	}

	pc := persistentCache{
		Entries:  validEntries,
		LastSave: now,
	}

	data, err := json.Marshal(pc)
	if err != nil {
		return
	}

	// Write to temporary file first
	tempFile := cacheFile + ".tmp"
	if err := os.WriteFile(tempFile, data, 0600); err != nil {
		return
	}

	// Atomic rename
	os.Rename(tempFile, cacheFile)
	policyCache.lastSave = now
}

// Add init function to load cache at startup
func init() {
	loadCache()
}
