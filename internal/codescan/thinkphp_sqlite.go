package codescan

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

// parseSQLiteURLConfig reads only the urlconfig-shaped tables from a snapshot
// copy. The database is untrusted input: every identifier is quoted, every
// query is bounded and the connection is read-only.
func parseSQLiteURLConfig(ctx context.Context, pathValue string) []urlConfigRow {
	runCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	db, err := sql.Open("sqlite", pathValue)
	if err != nil {
		return nil
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	if _, err = db.ExecContext(runCtx, "PRAGMA query_only = ON"); err != nil {
		return nil
	}

	tables, err := sqliteURLConfigTables(runCtx, db)
	if err != nil || len(tables) == 0 {
		return nil
	}
	rows := make([]urlConfigRow, 0, 64)
	for _, table := range tables {
		aliasColumn, urlColumn, ok := sqliteURLConfigColumns(runCtx, db, table)
		if !ok {
			continue
		}
		query := fmt.Sprintf("SELECT %s, %s FROM %s LIMIT %d",
			quoteSQLiteIdentifier(aliasColumn), quoteSQLiteIdentifier(urlColumn),
			quoteSQLiteIdentifier(table), MaxDatabaseRoutes)
		result, queryErr := db.QueryContext(runCtx, query)
		if queryErr != nil {
			continue
		}
		for result.Next() {
			var alias, target sql.NullString
			if scanErr := result.Scan(&alias, &target); scanErr != nil {
				continue
			}
			aliasValue := strings.TrimSpace(alias.String)
			targetValue := strings.TrimSpace(target.String)
			if !alias.Valid || aliasValue == "" || len(aliasValue) > 256 || len(targetValue) > 256 {
				continue
			}
			rows = append(rows, urlConfigRow{Alias: aliasValue, URL: targetValue})
			if len(rows) >= MaxDatabaseRoutes {
				break
			}
		}
		result.Close()
		if len(rows) >= MaxDatabaseRoutes {
			break
		}
	}
	return rows
}

func sqliteURLConfigTables(ctx context.Context, db *sql.DB) ([]string, error) {
	rows, err := db.QueryContext(ctx, `SELECT name FROM sqlite_master WHERE type = 'table' AND lower(name) LIKE '%urlconfig%' LIMIT 8`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	tables := make([]string, 0, 8)
	for rows.Next() {
		var name string
		if scanErr := rows.Scan(&name); scanErr == nil && strings.TrimSpace(name) != "" && len(name) <= 128 {
			tables = append(tables, name)
		}
	}
	return tables, rows.Err()
}

func sqliteURLConfigColumns(ctx context.Context, db *sql.DB, table string) (string, string, bool) {
	rows, err := db.QueryContext(ctx, "PRAGMA table_info("+quoteSQLiteIdentifier(table)+")")
	if err != nil {
		return "", "", false
	}
	defer rows.Close()
	aliasColumn, urlColumn := "", ""
	for rows.Next() {
		var (
			cid       int
			name      string
			columnTyp string
			notNull   int
			defaultV  sql.NullString
			primary   int
		)
		if scanErr := rows.Scan(&cid, &name, &columnTyp, &notNull, &defaultV, &primary); scanErr != nil {
			continue
		}
		switch strings.ToLower(strings.TrimSpace(name)) {
		case "aliases", "alias":
			if aliasColumn == "" {
				aliasColumn = name
			}
		case "url", "target", "path":
			if urlColumn == "" {
				urlColumn = name
			}
		}
	}
	return aliasColumn, urlColumn, aliasColumn != "" && urlColumn != ""
}

func quoteSQLiteIdentifier(name string) string {
	return `"` + strings.ReplaceAll(name, `"`, `""`) + `"`
}
