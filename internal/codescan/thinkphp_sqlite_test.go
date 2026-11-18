package codescan

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"testing"

	_ "modernc.org/sqlite"

	"trident/internal/project"
)

func sqliteURLConfigFixture(t *testing.T, statements ...string) string {
	t.Helper()
	pathValue := filepath.Join(t.TempDir(), "urlconfig.db")
	db, err := sql.Open("sqlite", pathValue)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for _, statement := range statements {
		if _, err = db.Exec(statement); err != nil {
			t.Fatalf("exec %q: %v", statement, err)
		}
	}
	return pathValue
}

func TestParseSQLiteURLConfigReadsAliasesAndURL(t *testing.T) {
	pathValue := sqliteURLConfigFixture(t,
		`CREATE TABLE urlconfig (id INTEGER PRIMARY KEY, aliases TEXT NOT NULL, url TEXT NOT NULL, status INTEGER)`,
		`INSERT INTO urlconfig (aliases, url, status) VALUES ('/news', 'News/index', 1)`,
		`INSERT INTO urlconfig (aliases, url, status) VALUES ('/about', 'About/index', 1)`,
	)
	rows := parseSQLiteURLConfig(context.Background(), pathValue)
	if len(rows) != 2 {
		t.Fatalf("sqlite rows: %+v", rows)
	}
	if rows[0].Alias != "/news" || rows[0].URL != "News/index" {
		t.Fatalf("first row: %+v", rows[0])
	}
}

func TestParseSQLiteURLConfigWithoutURLConfigTableReturnsNil(t *testing.T) {
	pathValue := sqliteURLConfigFixture(t, `CREATE TABLE settings (name TEXT, value TEXT)`)
	if rows := parseSQLiteURLConfig(context.Background(), pathValue); len(rows) != 0 {
		t.Fatalf("unexpected rows: %+v", rows)
	}
}

func TestLoadURLConfigRowsReadsSQLiteFromSnapshot(t *testing.T) {
	source := t.TempDir()
	databaseDir := filepath.Join(source, "database")
	if err := os.MkdirAll(databaseDir, 0o700); err != nil {
		t.Fatal(err)
	}
	dbPath := filepath.Join(databaseDir, "urlconfig.db")
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(`CREATE TABLE urlconfig (id INTEGER PRIMARY KEY, aliases TEXT, url TEXT)`); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(`INSERT INTO urlconfig (aliases, url) VALUES ('/sqlite-news', 'News/index')`); err != nil {
		t.Fatal(err)
	}
	if err = db.Close(); err != nil {
		t.Fatal(err)
	}
	if err = os.MkdirAll(filepath.Join(source, "app"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(source, "app", "route.php"), []byte("<?php\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	destination := filepath.Join(t.TempDir(), "snapshot")
	imported, err := project.Import(context.Background(), source, destination)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := project.Open(context.Background(), imported.Path, imported.Hash)
	if err != nil {
		t.Fatal(err)
	}
	defer snapshot.Close()
	rows := loadURLConfigRows(context.Background(), snapshot)
	if len(rows) != 1 || rows[0].Alias != "/sqlite-news" || rows[0].URL != "News/index" {
		t.Fatalf("snapshot sqlite rows: %+v", rows)
	}
}
