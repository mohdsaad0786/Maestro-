package providers

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/aws/smithy-go"
)

func TestProviderSelection(t *testing.T) {
	for _, name := range []string{"aws", "gcp", "azure"} {
		if scanner, err := New(name); err != nil || scanner == nil {
			t.Fatalf("provider %s: %v", name, err)
		}
	}
	if _, err := New("invalid"); err == nil {
		t.Fatal("unsupported provider accepted")
	}
}

func TestExpectedMissingAWSConfiguration(t *testing.T) {
	err := &smithy.GenericAPIError{Code: "NoSuchPublicAccessBlockConfiguration", Message: "not set"}
	if !apiCode(err, "NoSuchPublicAccessBlockConfiguration") {
		t.Fatal("expected S3 missing configuration error")
	}
	if apiCode(err, "AccessDenied") || apiCode(errors.New("unavailable"), "NoSuchPublicAccessBlockConfiguration") {
		t.Fatal("must not conflate missing config with access failure")
	}
}

func TestProjectAndSubscriptionRequired(t *testing.T) {
	t.Setenv("GOOGLE_CLOUD_PROJECT", "")
	t.Setenv("AZURE_SUBSCRIPTION_ID", "")
	if _, err := (gcpScanner{}).Discover(context.Background()); err == nil || !strings.Contains(err.Error(), "GOOGLE_CLOUD_PROJECT") {
		t.Fatalf("GCP: %v", err)
	}
	if _, err := (azureScanner{}).Discover(context.Background()); err == nil || !strings.Contains(err.Error(), "AZURE_SUBSCRIPTION_ID") {
		t.Fatalf("Azure: %v", err)
	}
}
