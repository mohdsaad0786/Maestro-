package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	_ "modernc.org/sqlite"

	"github.com/mohdsaad0786/maestro/backend/internal/core"
)

type Store struct {
	db       *sql.DB
	postgres bool
}

type Scan struct {
	ID        string `json:"id"`
	Provider  string `json:"provider"`
	Status    string `json:"status"`
	StartedAt string `json:"startedAt"`
	Message   string `json:"message,omitempty"`
	Resources int    `json:"resources"`
	Findings  int    `json:"findings"`
}

func Open(ctx context.Context, url string) (*Store, error) {
	postgres := strings.HasPrefix(url, "postgres://") || strings.HasPrefix(url, "postgresql://")
	driver := "sqlite"
	if postgres {
		driver = "pgx"
	}
	db, err := sql.Open(driver, url)
	if err != nil {
		return nil, err
	}
	if !postgres {
		db.SetMaxOpenConns(1)
	} else {
		db.SetMaxOpenConns(10)
	}
	store := &Store{db: db, postgres: postgres}
	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return nil, fmt.Errorf("database connection: %w", err)
	}
	for _, statement := range []string{
		`CREATE TABLE IF NOT EXISTS resources (id TEXT PRIMARY KEY, provider TEXT NOT NULL, kind TEXT NOT NULL, name TEXT NOT NULL, parent_id TEXT NOT NULL, region TEXT NOT NULL, attributes TEXT NOT NULL)`,
		`CREATE TABLE IF NOT EXISTS findings (id TEXT PRIMARY KEY, provider TEXT NOT NULL, rule_id TEXT NOT NULL, resource_id TEXT NOT NULL, title TEXT NOT NULL, severity TEXT NOT NULL, actual TEXT NOT NULL, frameworks TEXT NOT NULL, remediation TEXT NOT NULL)`,
		`CREATE TABLE IF NOT EXISTS scans (id TEXT PRIMARY KEY, provider TEXT NOT NULL, status TEXT NOT NULL, started_at TEXT NOT NULL, message TEXT NOT NULL, resources INTEGER NOT NULL, findings INTEGER NOT NULL)`,
		`CREATE INDEX IF NOT EXISTS resources_provider_idx ON resources(provider)`,
		`CREATE INDEX IF NOT EXISTS findings_provider_idx ON findings(provider)`,
		`CREATE INDEX IF NOT EXISTS scans_started_idx ON scans(started_at)`,
	} {
		if _, err := db.ExecContext(ctx, statement); err != nil {
			db.Close()
			return nil, fmt.Errorf("schema: %w", err)
		}
	}
	return store, nil
}

func (store *Store) Close() error                   { return store.db.Close() }
func (store *Store) Ping(ctx context.Context) error { return store.db.PingContext(ctx) }

func (store *Store) query(statement string) string {
	if !store.postgres {
		return statement
	}
	for index := 1; strings.Contains(statement, "?"); index++ {
		statement = strings.Replace(statement, "?", fmt.Sprintf("$%d", index), 1)
	}
	return statement
}

func (store *Store) Save(ctx context.Context, scan Scan, resources []core.Resource, findings []core.Finding) error {
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, table := range []string{"findings", "resources"} {
		if _, err := tx.ExecContext(ctx, store.query("DELETE FROM "+table+" WHERE provider = ?"), scan.Provider); err != nil {
			return err
		}
	}
	for _, resource := range resources {
		attributes, err := json.Marshal(resource.Attributes)
		if err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, store.query(`INSERT INTO resources (id,provider,kind,name,parent_id,region,attributes) VALUES (?,?,?,?,?,?,?)`), resource.ID, resource.Provider, resource.Kind, resource.Name, resource.ParentID, resource.Region, string(attributes))
		if err != nil {
			return fmt.Errorf("save resource: %w", err)
		}
	}
	for _, finding := range findings {
		frameworks, err := json.Marshal(finding.Frameworks)
		if err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, store.query(`INSERT INTO findings (id,provider,rule_id,resource_id,title,severity,actual,frameworks,remediation) VALUES (?,?,?,?,?,?,?,?,?)`), finding.ID, scan.Provider, finding.RuleID, finding.ResourceID, finding.Title, finding.Severity, finding.Actual, string(frameworks), finding.Remediation)
		if err != nil {
			return fmt.Errorf("save finding: %w", err)
		}
	}
	if err := store.insertScan(ctx, tx, scan); err != nil {
		return err
	}
	return tx.Commit()
}

func (store *Store) Failure(ctx context.Context, scan Scan) error {
	return store.insertScan(ctx, store.db, scan)
}

type executor interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
}

func (store *Store) insertScan(ctx context.Context, db executor, scan Scan) error {
	_, err := db.ExecContext(ctx, store.query(`INSERT INTO scans (id,provider,status,started_at,message,resources,findings) VALUES (?,?,?,?,?,?,?)`), scan.ID, scan.Provider, scan.Status, scan.StartedAt, scan.Message, scan.Resources, scan.Findings)
	return err
}

func (store *Store) Resources(ctx context.Context, limit, offset int) ([]core.Resource, error) {
	rows, err := store.db.QueryContext(ctx, store.query(`SELECT id,provider,kind,name,parent_id,region,attributes FROM resources ORDER BY provider,id LIMIT ? OFFSET ?`), limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]core.Resource, 0)
	for rows.Next() {
		var item core.Resource
		var attributes string
		if err := rows.Scan(&item.ID, &item.Provider, &item.Kind, &item.Name, &item.ParentID, &item.Region, &attributes); err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(attributes), &item.Attributes); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (store *Store) Findings(ctx context.Context, limit, offset int) ([]core.Finding, error) {
	rows, err := store.db.QueryContext(ctx, store.query(`SELECT id,rule_id,resource_id,title,severity,actual,frameworks,remediation FROM findings ORDER BY severity,id LIMIT ? OFFSET ?`), limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]core.Finding, 0)
	for rows.Next() {
		var item core.Finding
		var frameworks string
		if err := rows.Scan(&item.ID, &item.RuleID, &item.ResourceID, &item.Title, &item.Severity, &item.Actual, &frameworks, &item.Remediation); err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(frameworks), &item.Frameworks); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (store *Store) Scans(ctx context.Context, limit int) ([]Scan, error) {
	rows, err := store.db.QueryContext(ctx, store.query(`SELECT id,provider,status,started_at,message,resources,findings FROM scans ORDER BY started_at DESC,id DESC LIMIT ?`), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]Scan, 0)
	for rows.Next() {
		var item Scan
		if err := rows.Scan(&item.ID, &item.Provider, &item.Status, &item.StartedAt, &item.Message, &item.Resources, &item.Findings); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func NewScan(provider string) Scan {
	now := time.Now().UTC()
	return Scan{ID: core.ID(provider, now.Format(time.RFC3339Nano)), Provider: provider, StartedAt: now.Format(time.RFC3339Nano)}
}
