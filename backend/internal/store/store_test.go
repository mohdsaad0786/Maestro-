package store

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/mohdsaad0786/maestro/backend/internal/core"
)

func TestSnapshotIsolationAndPersistence(t *testing.T) {
	testSnapshotIsolationAndPersistence(t, filepath.Join(t.TempDir(), "maestro.db"))
}

func TestPostgresSnapshot(t *testing.T) {
	url := os.Getenv("MAESTRO_TEST_POSTGRES_URL")
	if url == "" {
		t.Skip("set MAESTRO_TEST_POSTGRES_URL for PostgreSQL integration")
	}
	testSnapshotIsolationAndPersistence(t, url)
}

func testSnapshotIsolationAndPersistence(t *testing.T, url string) {
	t.Helper()
	ctx := context.Background()
	database, err := Open(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	runID := core.ID(t.Name(), time.Now().UTC().Format(time.RFC3339Nano))
	resource := core.Resource{ID: "aws:s3:bucket:" + runID, Provider: "aws", Kind: "bucket", Name: "a", ParentID: "aws:account:123", Attributes: map[string]string{"publicAccessBlocked": "false", "defaultEncryption": "true"}}
	findings, err := core.Evaluate([]core.Resource{resource})
	if err != nil {
		t.Fatal(err)
	}
	scan := NewScan("aws")
	scan.Status = "completed"
	if err := database.Save(ctx, scan, []core.Resource{resource}, findings); err != nil {
		t.Fatal(err)
	}
	if err := database.Save(ctx, NewScan("aws"), []core.Resource{resource, resource}, findings); err == nil {
		t.Fatal("duplicate resource should rollback snapshot")
	}
	failedID := core.ID("failed", runID)
	if err := database.Failure(ctx, Scan{ID: failedID, Provider: "aws", Status: "failed", StartedAt: "2026-01-01T00:00:00Z", Message: "test"}); err != nil {
		t.Fatal(err)
	}
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}
	database, err = Open(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	stored, err := database.Resources(ctx, 100, 0)
	if err != nil || len(stored) != 1 || stored[0].ID != resource.ID {
		t.Fatalf("previous snapshot not retained: %+v %v", stored, err)
	}
	storedFindings, err := database.Findings(ctx, 100, 0)
	if err != nil || len(storedFindings) != 1 || storedFindings[0].ID != findings[0].ID {
		t.Fatalf("finding missing: %+v %v", storedFindings, err)
	}
	scans, err := database.Scans(ctx, 1000)
	if err != nil {
		t.Fatal(err)
	}
	seenSuccess, seenFailure := false, false
	for _, recorded := range scans {
		if recorded.ID == scan.ID {
			seenSuccess = recorded.Status == "completed"
		}
		if recorded.ID == failedID {
			seenFailure = recorded.Status == "failed"
		}
	}
	if !seenSuccess || !seenFailure {
		t.Fatalf("expected successful and failed runs: %+v", scans)
	}
}
