package core

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

type Resource struct {
	ID         string            `json:"id"`
	Provider   string            `json:"provider"`
	Kind       string            `json:"kind"`
	Name       string            `json:"name"`
	ParentID   string            `json:"parentId,omitempty"`
	Region     string            `json:"region,omitempty"`
	Attributes map[string]string `json:"attributes"`
}

type Rule struct {
	ID          string   `json:"id"`
	Provider    string   `json:"provider"`
	Kind        string   `json:"kind"`
	Title       string   `json:"title"`
	Severity    string   `json:"severity"`
	Field       string   `json:"field"`
	Expected    string   `json:"expected"`
	Frameworks  []string `json:"frameworks"`
	Remediation string   `json:"remediation"`
}

type Finding struct {
	ID          string   `json:"id"`
	RuleID      string   `json:"ruleId"`
	ResourceID  string   `json:"resourceId"`
	Title       string   `json:"title"`
	Severity    string   `json:"severity"`
	Actual      string   `json:"actual"`
	Frameworks  []string `json:"frameworks"`
	Remediation string   `json:"remediation"`
}

type Edge struct {
	Source string `json:"source"`
	Target string `json:"target"`
	Type   string `json:"type"`
}

var Rules = []Rule{
	{ID: "aws.s3.public_access_block", Provider: "aws", Kind: "bucket", Title: "Set bucket-level public access block", Severity: "high", Field: "publicAccessBlocked", Expected: "true", Frameworks: []string{"CIS AWS", "SOC 2"}, Remediation: "# In your aws_s3_bucket_public_access_block resource:\nblock_public_acls = true\nblock_public_policy = true\nignore_public_acls = true\nrestrict_public_buckets = true"},
	{ID: "aws.s3.default_encryption", Provider: "aws", Kind: "bucket", Title: "Enable S3 default encryption", Severity: "high", Field: "defaultEncryption", Expected: "true", Frameworks: []string{"CIS AWS", "PCI DSS", "HIPAA Security Rule"}, Remediation: "# In your aws_s3_bucket_server_side_encryption_configuration resource:\nrule { apply_server_side_encryption_by_default { sse_algorithm = \"AES256\" } }"},
	{ID: "gcp.gcs.uniform_access", Provider: "gcp", Kind: "bucket", Title: "Enforce uniform bucket-level access", Severity: "high", Field: "uniformAccess", Expected: "true", Frameworks: []string{"CIS GCP", "SOC 2"}, Remediation: "# In your existing google_storage_bucket resource:\nuniform_bucket_level_access = true"},
	{ID: "gcp.gcs.public_access_prevention", Provider: "gcp", Kind: "bucket", Title: "Explicitly enforce bucket public access prevention", Severity: "medium", Field: "publicAccessPrevention", Expected: "enforced", Frameworks: []string{"CIS GCP", "SOC 2"}, Remediation: "# Check whether an organization policy already enforces this. In your google_storage_bucket resource:\npublic_access_prevention = \"enforced\""},
	{ID: "azure.storage.https_only", Provider: "azure", Kind: "storage_account", Title: "Require secure transfer", Severity: "high", Field: "httpsOnly", Expected: "true", Frameworks: []string{"CIS Azure", "PCI DSS", "HIPAA Security Rule"}, Remediation: "# In your existing azurerm_storage_account resource:\nhttps_traffic_only_enabled = true"},
	{ID: "azure.storage.public_blob_access", Provider: "azure", Kind: "storage_account", Title: "Disallow account-level public blob access", Severity: "high", Field: "publicBlobAccess", Expected: "false", Frameworks: []string{"CIS Azure", "SOC 2"}, Remediation: "# In your existing azurerm_storage_account resource:\nallow_nested_items_to_be_public = false"},
	{ID: "azure.storage.tls12", Provider: "azure", Kind: "storage_account", Title: "Require TLS 1.2 or newer", Severity: "high", Field: "tlsAtLeast12", Expected: "true", Frameworks: []string{"CIS Azure", "PCI DSS"}, Remediation: "# In your existing azurerm_storage_account resource:\nmin_tls_version = \"TLS1_2\""},
}

func ID(parts ...string) string {
	sum := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return hex.EncodeToString(sum[:16])
}

func ValidateSnapshot(provider string, resources []Resource) error {
	if len(resources) == 0 {
		return errors.New("discovery returned no account or project root")
	}
	ids := make(map[string]bool, len(resources))
	children := make(map[string][]string, len(resources))
	roots := 0
	rootID := ""
	for _, resource := range resources {
		if resource.Provider != provider || resource.ID == "" || ids[resource.ID] {
			return fmt.Errorf("invalid or duplicate resource in %s snapshot: %q", provider, resource.ID)
		}
		ids[resource.ID] = true
		if resource.ParentID == "" {
			roots++
			rootID = resource.ID
		} else {
			children[resource.ParentID] = append(children[resource.ParentID], resource.ID)
		}
	}
	if roots != 1 {
		return fmt.Errorf("%s snapshot must have exactly one account or project root", provider)
	}
	for _, resource := range resources {
		if resource.ParentID != "" && !ids[resource.ParentID] {
			return fmt.Errorf("%s: missing parent %s", resource.ID, resource.ParentID)
		}
	}
	visited := map[string]bool{rootID: true}
	queue := []string{rootID}
	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]
		for _, child := range children[current] {
			if !visited[child] {
				visited[child] = true
				queue = append(queue, child)
			}
		}
	}
	if len(visited) != len(resources) {
		return fmt.Errorf("%s snapshot contains orphaned or cyclic relationships", provider)
	}
	return nil
}

func Evaluate(resources []Resource) ([]Finding, error) {
	findings := make([]Finding, 0)
	seen := make(map[string]bool, len(resources))
	for _, resource := range resources {
		if resource.ID == "" || resource.Provider == "" || resource.Kind == "" || seen[resource.ID] {
			return nil, fmt.Errorf("invalid or duplicate resource: %q", resource.ID)
		}
		seen[resource.ID] = true
		for _, rule := range Rules {
			if rule.Provider != resource.Provider || rule.Kind != resource.Kind {
				continue
			}
			actual, ok := resource.Attributes[rule.Field]
			if !ok {
				return nil, fmt.Errorf("%s: %w: %s", resource.ID, errors.New("missing evaluated attribute"), rule.Field)
			}
			if actual != rule.Expected {
				findings = append(findings, Finding{ID: ID(rule.ID, resource.ID), RuleID: rule.ID, ResourceID: resource.ID, Title: rule.Title, Severity: rule.Severity, Actual: actual, Frameworks: rule.Frameworks, Remediation: rule.Remediation})
			}
		}
	}
	return findings, nil
}
