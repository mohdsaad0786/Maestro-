package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/mohdsaad0786/maestro/backend/internal/core"
	"github.com/mohdsaad0786/maestro/backend/internal/providers"
	"github.com/mohdsaad0786/maestro/backend/internal/store"
)

type fakeScanner struct{}

func (fakeScanner) Discover(context.Context) ([]core.Resource, error) {
	return []core.Resource{
		{ID: "aws:account:123", Provider: "aws", Kind: "account", Name: "123", Attributes: map[string]string{}},
		{ID: "aws:s3:bucket:demo", Provider: "aws", Kind: "bucket", Name: "demo", ParentID: "aws:account:123", Attributes: map[string]string{"publicAccessBlocked": "false", "defaultEncryption": "true"}},
	}, nil
}

func TestAuthAndScan(t *testing.T) {
	database, err := store.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	token := strings.Repeat("a", 32)
	server := &Server{Store: database, Token: token, Scanner: func(name string) (providers.Scanner, error) { return fakeScanner{}, nil }}
	handler := server.Handler()
	call := func(method, path, body, secret string) *httptest.ResponseRecorder {
		t.Helper()
		request := httptest.NewRequest(method, path, strings.NewReader(body))
		if secret != "" {
			request.Header.Set("Authorization", "Bearer "+secret)
		}
		if body != "" {
			request.Header.Set("Content-Type", "application/json")
		}
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		return response
	}
	if got := call("GET", "/healthz", "", "").Code; got != http.StatusNoContent {
		t.Fatalf("liveness: %d", got)
	}
	if got := call("GET", "/api/v1/resources", "", "").Code; got != http.StatusUnauthorized {
		t.Fatalf("unauthenticated: %d", got)
	}
	if got := call("GET", "/metrics", "", "bad").Code; got != http.StatusUnauthorized {
		t.Fatalf("metrics authentication: %d", got)
	}
	if got := call("POST", "/api/v1/scans", `{"provider":"aws","extra":true}`, token).Code; got != http.StatusBadRequest {
		t.Fatalf("unknown fields: %d", got)
	}
	if got := call("POST", "/api/v1/scans", `{"provider":"aws"}`, token).Code; got != http.StatusOK {
		t.Fatalf("scan: %d", got)
	}
	if got := call("GET", "/api/v1/findings", "", token); got.Code != http.StatusOK || !strings.Contains(got.Body.String(), "public_access_block") {
		t.Fatalf("findings: %d %s", got.Code, got.Body.String())
	}
	if got := call("GET", "/api/v1/graph", "", token); got.Code != http.StatusOK || !strings.Contains(got.Body.String(), "belongs_to") {
		t.Fatalf("graph: %d %s", got.Code, got.Body.String())
	}
	if got := call("GET", "/metrics", "", token); got.Code != http.StatusOK || !strings.Contains(got.Body.String(), `maestro_scans_total{provider="aws",status="completed"} 1`) {
		t.Fatalf("metrics: %d %s", got.Code, got.Body.String())
	}
}
