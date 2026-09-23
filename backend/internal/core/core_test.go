package core

import (
	"fmt"
	"testing"
)

func sample() []Resource {
	return []Resource{
		{ID: "aws:s3:bucket:example", Provider: "aws", Kind: "bucket", Name: "example", Attributes: map[string]string{"publicAccessBlocked": "false", "defaultEncryption": "true"}},
		{ID: "gcp:gcs:bucket:example", Provider: "gcp", Kind: "bucket", Name: "example", Attributes: map[string]string{"uniformAccess": "true", "publicAccessPrevention": "inherited"}},
		{ID: "azure:storage:example", Provider: "azure", Kind: "storage_account", Name: "example", Attributes: map[string]string{"httpsOnly": "true", "publicBlobAccess": "false", "tlsAtLeast12": "true"}},
	}
}

func TestEvaluate(t *testing.T) {
	first, err := Evaluate(sample())
	if err != nil {
		t.Fatal(err)
	}
	second, err := Evaluate(sample())
	if err != nil {
		t.Fatal(err)
	}
	if len(first) != 2 || len(second) != 2 {
		t.Fatalf("expected two actionable findings, got %d and %d", len(first), len(second))
	}
	for index, finding := range first {
		if finding.ID != second[index].ID || finding.ID == "" || len(finding.Frameworks) == 0 || finding.Remediation == "" {
			t.Errorf("non-deterministic or incomplete finding: %+v", finding)
		}
	}
}

func TestMissingConfigurationAborts(t *testing.T) {
	resources := sample()
	delete(resources[0].Attributes, "publicAccessBlocked")
	if _, err := Evaluate(resources); err == nil {
		t.Fatal("missing security attribute must not silently pass")
	}
}

func TestDuplicateResourceAborts(t *testing.T) {
	resources := sample()
	resources = append(resources, resources[0])
	if _, err := Evaluate(resources); err == nil {
		t.Fatal("duplicate IDs must not overwrite findings")
	}
}

func TestValidateSnapshot(t *testing.T) {
	root := Resource{ID: "aws:account:123", Provider: "aws", Kind: "account"}
	child := Resource{ID: "aws:s3:bucket:example", ParentID: root.ID, Provider: "aws", Kind: "bucket"}
	if err := ValidateSnapshot("aws", []Resource{root, child}); err != nil {
		t.Fatal(err)
	}
	for _, resources := range [][]Resource{{}, {child}, {root, {ID: "gcp:project:test", Provider: "gcp", Kind: "project"}}, {root, root}, {root, {ID: "a", Provider: "aws", ParentID: "b"}, {ID: "b", Provider: "aws", ParentID: "a"}}} {
		if err := ValidateSnapshot("aws", resources); err == nil {
			t.Fatalf("accepted incomplete snapshot: %+v", resources)
		}
	}
}

func BenchmarkEvaluate(b *testing.B) {
	resources := make([]Resource, 1000)
	for index := range resources {
		resources[index] = Resource{ID: fmt.Sprintf("aws:s3:bucket:%d", index), Provider: "aws", Kind: "bucket", Attributes: map[string]string{"publicAccessBlocked": "true", "defaultEncryption": "false"}}
	}
	b.ResetTimer()
	for index := 0; index < b.N; index++ {
		if _, err := Evaluate(resources); err != nil {
			b.Fatal(err)
		}
	}
}
