package api

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/mohdsaad0786/maestro/backend/internal/core"
	"github.com/mohdsaad0786/maestro/backend/internal/providers"
	"github.com/mohdsaad0786/maestro/backend/internal/store"
)

type Server struct {
	Store   *store.Store
	Token   string
	Scanner func(string) (providers.Scanner, error)
	busy    atomic.Bool
	metrics [3][2]scanMetrics
}

type scanMetrics struct {
	count   atomic.Uint64
	nanos   atomic.Uint64
	buckets [6]atomic.Uint64
}

var providersList = []string{"aws", "gcp", "azure"}
var durations = []float64{0.5, 1, 5, 15, 60, 180}

func (server *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(writer http.ResponseWriter, _ *http.Request) { writer.WriteHeader(http.StatusNoContent) })
	mux.HandleFunc("GET /readyz", func(writer http.ResponseWriter, request *http.Request) {
		if err := server.Store.Ping(request.Context()); err != nil {
			http.Error(writer, "not ready", http.StatusServiceUnavailable)
			return
		}
		writer.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("GET /metrics", server.serveMetrics)
	mux.HandleFunc("GET /api/v1/rules", func(writer http.ResponseWriter, _ *http.Request) { respond(writer, http.StatusOK, core.Rules) })
	mux.HandleFunc("GET /api/v1/resources", func(writer http.ResponseWriter, request *http.Request) {
		limit, offset, ok := page(writer, request)
		if !ok {
			return
		}
		items, err := server.Store.Resources(request.Context(), limit, offset)
		if err != nil {
			internalError(writer, err)
			return
		}
		respond(writer, http.StatusOK, items)
	})
	mux.HandleFunc("GET /api/v1/findings", func(writer http.ResponseWriter, request *http.Request) {
		limit, offset, ok := page(writer, request)
		if !ok {
			return
		}
		items, err := server.Store.Findings(request.Context(), limit, offset)
		if err != nil {
			internalError(writer, err)
			return
		}
		respond(writer, http.StatusOK, items)
	})
	mux.HandleFunc("GET /api/v1/graph", func(writer http.ResponseWriter, request *http.Request) {
		limit, offset, ok := page(writer, request)
		if !ok {
			return
		}
		items, err := server.Store.Resources(request.Context(), limit, offset)
		if err != nil {
			internalError(writer, err)
			return
		}
		edges := make([]core.Edge, 0)
		for _, resource := range items {
			if resource.ParentID != "" {
				edges = append(edges, core.Edge{Source: resource.ID, Target: resource.ParentID, Type: "belongs_to"})
			}
		}
		respond(writer, http.StatusOK, struct {
			Nodes []core.Resource `json:"nodes"`
			Edges []core.Edge     `json:"edges"`
		}{items, edges})
	})
	mux.HandleFunc("GET /api/v1/scans", func(writer http.ResponseWriter, request *http.Request) {
		items, err := server.Store.Scans(request.Context(), 50)
		if err != nil {
			internalError(writer, err)
			return
		}
		respond(writer, http.StatusOK, items)
	})
	mux.HandleFunc("POST /api/v1/scans", server.scan)
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/healthz" && request.URL.Path != "/readyz" {
			given := strings.TrimPrefix(request.Header.Get("Authorization"), "Bearer ")
			if !strings.HasPrefix(request.Header.Get("Authorization"), "Bearer ") || !authorized(given, server.Token) {
				writer.Header().Set("WWW-Authenticate", "Bearer")
				http.Error(writer, "unauthorized", http.StatusUnauthorized)
				return
			}
		}
		mux.ServeHTTP(writer, request)
	})
}

func authorized(given, expected string) bool {
	if given == "" || expected == "" {
		return false
	}
	left, right := sha256.Sum256([]byte(given)), sha256.Sum256([]byte(expected))
	return subtle.ConstantTimeCompare(left[:], right[:]) == 1
}

func page(writer http.ResponseWriter, request *http.Request) (int, int, bool) {
	limit, offset := 100, 0
	for key, destination := range map[string]*int{"limit": &limit, "offset": &offset} {
		if text := request.URL.Query().Get(key); text != "" {
			value, err := strconv.Atoi(text)
			if err != nil {
				http.Error(writer, "invalid pagination", http.StatusBadRequest)
				return 0, 0, false
			}
			*destination = value
		}
	}
	if limit < 1 || limit > 1000 || offset < 0 {
		http.Error(writer, "invalid pagination", http.StatusBadRequest)
		return 0, 0, false
	}
	return limit, offset, true
}

func (server *Server) scan(writer http.ResponseWriter, request *http.Request) {
	if request.Header.Get("Content-Type") != "application/json" {
		http.Error(writer, "expected application/json", http.StatusUnsupportedMediaType)
		return
	}
	var input struct {
		Provider string `json:"provider"`
	}
	decoder := json.NewDecoder(io.LimitReader(request.Body, 4096))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&input); err != nil {
		http.Error(writer, "invalid JSON", http.StatusBadRequest)
		return
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		http.Error(writer, "unexpected JSON content", http.StatusBadRequest)
		return
	}
	scannerFactory := server.Scanner
	if scannerFactory == nil {
		scannerFactory = providers.New
	}
	scanner, err := scannerFactory(input.Provider)
	if err != nil {
		http.Error(writer, "unsupported provider", http.StatusBadRequest)
		return
	}
	if !server.busy.CompareAndSwap(false, true) {
		http.Error(writer, "scan already in progress", http.StatusConflict)
		return
	}
	defer server.busy.Store(false)
	started := time.Now()
	scan := store.NewScan(input.Provider)
	ctx, cancel := context.WithTimeout(request.Context(), 3*time.Minute)
	defer cancel()
	resources, err := scanner.Discover(ctx)
	var findings []core.Finding
	if err == nil {
		err = core.ValidateSnapshot(input.Provider, resources)
	}
	if err == nil {
		findings, err = core.Evaluate(resources)
	}
	if err == nil {
		scan.Status = "completed"
		scan.Resources, scan.Findings = len(resources), len(findings)
		err = server.Store.Save(ctx, scan, resources, findings)
	}
	server.observe(input.Provider, err != nil, time.Since(started))
	if err != nil {
		slog.Error("scan failed", "provider", input.Provider, "scan_id", scan.ID, "error", err)
		scan.Status, scan.Message = "failed", "Discovery, evaluation, or persistence failed; previous snapshot retained"
		failureCtx, failureCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer failureCancel()
		if recordErr := server.Store.Failure(failureCtx, scan); recordErr != nil {
			slog.Error("failed to record scan", "error", recordErr)
		}
		respond(writer, http.StatusBadGateway, scan)
		return
	}
	slog.Info("scan completed", "provider", scan.Provider, "scan_id", scan.ID, "resources", scan.Resources, "findings", scan.Findings)
	respond(writer, http.StatusOK, scan)
}

func (server *Server) observe(provider string, failed bool, elapsed time.Duration) {
	for index, value := range providersList {
		if provider != value {
			continue
		}
		status := 0
		if failed {
			status = 1
		}
		metric := &server.metrics[index][status]
		metric.count.Add(1)
		metric.nanos.Add(uint64(elapsed.Nanoseconds()))
		for bucket, boundary := range durations {
			if elapsed.Seconds() <= boundary {
				metric.buckets[bucket].Add(1)
			}
		}
		return
	}
}

func (server *Server) serveMetrics(writer http.ResponseWriter, _ *http.Request) {
	writer.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	fmt.Fprintln(writer, "# TYPE maestro_scans_total counter")
	fmt.Fprintln(writer, "# TYPE maestro_scan_duration_seconds histogram")
	for index, provider := range providersList {
		for state, status := range []string{"completed", "failed"} {
			metric := &server.metrics[index][state]
			labels := fmt.Sprintf("provider=%q,status=%q", provider, status)
			fmt.Fprintf(writer, "maestro_scans_total{%s} %d\n", labels, metric.count.Load())
			for bucket, boundary := range durations {
				fmt.Fprintf(writer, "maestro_scan_duration_seconds_bucket{%s,le=%q} %d\n", labels, strconv.FormatFloat(boundary, 'f', -1, 64), metric.buckets[bucket].Load())
			}
			fmt.Fprintf(writer, "maestro_scan_duration_seconds_bucket{%s,le=\"+Inf\"} %d\n", labels, metric.count.Load())
			fmt.Fprintf(writer, "maestro_scan_duration_seconds_sum{%s} %g\n", labels, float64(metric.nanos.Load())/float64(time.Second))
			fmt.Fprintf(writer, "maestro_scan_duration_seconds_count{%s} %d\n", labels, metric.count.Load())
		}
	}
}

func respond(writer http.ResponseWriter, status int, value any) {
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(status)
	if err := json.NewEncoder(writer).Encode(value); err != nil {
		slog.Error("encode response", "error", err)
	}
}

func internalError(writer http.ResponseWriter, err error) {
	slog.Error("database operation failed", "error", err)
	http.Error(writer, "internal error", http.StatusInternalServerError)
}
