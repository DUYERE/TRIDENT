// Package db 提供显式、只向前的数据库迁移与只读版本检查。
// 已发布的迁移不可修改或删除；修复必须新增向前迁移，不提供破坏性 down。
package db

import (
	"context"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// [01] SQL 与二进制一起发布；每个文件是一个不含手写 BEGIN/COMMIT 的向前迁移。
//
//go:embed migrations/*.sql
var migrationFiles embed.FS

const (
	// [02] 固定会话锁标识：同一数据库的 TRIDENT 迁移必须串行执行。
	migrationLockKey int64 = 0x54524944454e5401
	cleanupTimeout         = 5 * time.Second
)

type migration struct {
	version  string
	checksum string
	sql      string
}

// Migrate 显式执行嵌入的向前迁移，不创建数据库。
// actor 必须是非空白主体；version 保存完整 SQL 文件名，checksum 是原始文件字节的 SHA-256。
// 已发布迁移的任何变化、数据库中的未知版本及任一 SQL 错误都会阻止继续执行。
func Migrate(ctx context.Context, pool *pgxpool.Pool, actor string) (retErr error) {
	// [03] 先验证本地输入，避免无主体迁移或无效清单访问数据库。
	if err := validateActor(actor); err != nil {
		return err
	}
	if pool == nil {
		return errors.New("migrate: pool is nil")
	}
	migrations, err := loadMigrations(migrationFiles)
	if err != nil {
		return err
	}

	// [04] 锁、历史读取及所有事务共用同一条连接，不使用 pool.Exec 切换会话。
	conn, err := pool.Acquire(ctx)
	if err != nil {
		return fmt.Errorf("migrate: acquire connection: %w", err)
	}
	locked := false
	defer func() {
		retErr = errors.Join(retErr, releaseMigrationConnection(conn, locked))
	}()
	if _, err := conn.Exec(ctx, "SELECT pg_advisory_lock($1)", migrationLockKey); err != nil {
		return fmt.Errorf("migrate: acquire advisory lock: %w", err)
	}
	locked = true

	// [05] 仅显式 Migrate 创建元数据表；此处不执行 CREATE DATABASE。
	if _, err := conn.Exec(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (
		version text PRIMARY KEY,
		checksum text NOT NULL,
		applied_at timestamptz NOT NULL DEFAULT clock_timestamp(),
		applied_by text NOT NULL
	)`); err != nil {
		return fmt.Errorf("migrate: create schema_migrations: %w", err)
	}
	applied, err := readApplied(ctx, conn)
	if err != nil {
		return err
	}
	// [06] 在执行任何迁移前完整检查历史，拒绝篡改及旧二进制操作新数据库。
	if err := validateHistory(migrations, applied, false); err != nil {
		return fmt.Errorf("migrate: %w", err)
	}
	for _, m := range migrations {
		if _, exists := applied[m.version]; exists {
			continue
		}
		if err := applyMigration(ctx, conn, m, actor); err != nil {
			return err
		}
	}
	return nil
}

// Check 在只读事务中验证全部嵌入迁移已经应用，且历史版本及校验和完全匹配。
// 它不建表、不执行 DDL、不申请迁移锁；未连接、权限不足或尚未迁移均返回具体错误。
func Check(ctx context.Context, pool *pgxpool.Pool) (retErr error) {
	if pool == nil {
		return errors.New("check migrations: pool is nil")
	}
	migrations, err := loadMigrations(migrationFiles)
	if err != nil {
		return err
	}
	// [07] 只读、可重复读快照避免检查过程读到不同时间点的迁移历史。
	tx, err := pool.BeginTx(ctx, pgx.TxOptions{
		IsoLevel:   pgx.RepeatableRead,
		AccessMode: pgx.ReadOnly,
	})
	if err != nil {
		return fmt.Errorf("check migrations: begin read-only transaction: %w", err)
	}
	defer func() {
		retErr = errors.Join(retErr, rollbackTransaction(tx))
	}()
	applied, err := readApplied(ctx, tx)
	if err != nil {
		return fmt.Errorf("check migrations: %w", err)
	}
	if err := validateHistory(migrations, applied, true); err != nil {
		return fmt.Errorf("check migrations: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("check migrations: commit read-only transaction: %w", err)
	}
	return nil
}

func validateActor(actor string) error {
	if strings.TrimSpace(actor) == "" {
		return errors.New("migrate: actor must not be empty or whitespace")
	}
	return nil
}

func loadMigrations(files fs.FS) ([]migration, error) {
	entries, err := fs.ReadDir(files, "migrations")
	if err != nil {
		return nil, fmt.Errorf("migrate: list embedded migrations: %w", err)
	}
	var migrations []migration
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".sql") {
			continue
		}
		name := entry.Name()
		data, err := fs.ReadFile(files, "migrations/"+name)
		if err != nil {
			return nil, fmt.Errorf("migrate: read migration %q: %w", name, err)
		}
		if strings.TrimSpace(string(data)) == "" {
			return nil, fmt.Errorf("migrate: migration %q is empty", name)
		}
		// [08] 对原始字节计算校验和，不正规化换行、空白或 SQL 内容。
		sum := sha256.Sum256(data)
		migrations = append(migrations, migration{
			version:  name,
			checksum: hex.EncodeToString(sum[:]),
			sql:      string(data),
		})
	}
	if len(migrations) == 0 {
		return nil, errors.New("migrate: no embedded SQL migrations found")
	}
	// [09] 文件名按字典序排序；文件名应使用固定宽度版本前缀。
	sort.Slice(migrations, func(i, j int) bool {
		return migrations[i].version < migrations[j].version
	})
	return migrations, nil
}

type migrationQuerier interface {
	Query(context.Context, string, ...any) (pgx.Rows, error)
}

func readApplied(ctx context.Context, q migrationQuerier) (map[string]string, error) {
	rows, err := q.Query(ctx, "SELECT version, checksum FROM schema_migrations ORDER BY version")
	if err != nil {
		return nil, fmt.Errorf("migrate: read schema_migrations: %w", err)
	}
	defer rows.Close()
	applied := make(map[string]string)
	for rows.Next() {
		var version, checksum string
		if err := rows.Scan(&version, &checksum); err != nil {
			return nil, fmt.Errorf("migrate: scan schema_migrations: %w", err)
		}
		applied[version] = checksum
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("migrate: iterate schema_migrations: %w", err)
	}
	return applied, nil
}

func validateHistory(migrations []migration, applied map[string]string, requireAll bool) error {
	known := make(map[string]string, len(migrations))
	for _, m := range migrations {
		known[m.version] = m.checksum
	}
	versions := make([]string, 0, len(applied))
	for version := range applied {
		versions = append(versions, version)
	}
	sort.Strings(versions)
	for _, version := range versions {
		expected, ok := known[version]
		if !ok {
			return fmt.Errorf("database contains unknown migration %q; use a matching or newer binary", version)
		}
		if actual := applied[version]; actual != expected {
			return fmt.Errorf("migration %q checksum mismatch: database=%q binary=%q; add a forward repair migration instead of editing applied SQL", version, actual, expected)
		}
	}
	if requireAll {
		for _, m := range migrations {
			if _, ok := applied[m.version]; !ok {
				return fmt.Errorf("migration %q is not applied; run explicit migration", m.version)
			}
		}
	}
	return nil
}

func applyMigration(ctx context.Context, conn *pgxpool.Conn, m migration, actor string) (retErr error) {
	tx, err := conn.Begin(ctx)
	if err != nil {
		return fmt.Errorf("migrate %q: begin transaction: %w", m.version, err)
	}
	defer func() {
		retErr = errors.Join(retErr, rollbackTransaction(tx))
	}()
	// [10] SimpleProtocol 支持文件中的多条 SQL；SQL 与历史登记必须在同一事务提交。
	if _, err := tx.Exec(ctx, m.sql, pgx.QueryExecModeSimpleProtocol); err != nil {
		return fmt.Errorf("migrate %q: execute SQL: %w", m.version, err)
	}
	if _, err := tx.Exec(ctx,
		"INSERT INTO schema_migrations (version, checksum, applied_by) VALUES ($1, $2, $3)",
		m.version, m.checksum, actor,
	); err != nil {
		return fmt.Errorf("migrate %q: record migration: %w", m.version, err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("migrate %q: commit transaction: %w", m.version, err)
	}
	return nil
}

func rollbackTransaction(tx pgx.Tx) error {
	// [11] 调用者取消不会阻止回滚；保留真正的回滚错误，不覆盖原始失败原因。
	ctx, cancel := context.WithTimeout(context.Background(), cleanupTimeout)
	defer cancel()
	if err := tx.Rollback(ctx); err != nil && !errors.Is(err, pgx.ErrTxClosed) {
		return fmt.Errorf("migrate: rollback transaction: %w", err)
	}
	return nil
}

func releaseMigrationConnection(conn *pgxpool.Conn, locked bool) (retErr error) {
	// [12] 会话锁必须在同一连接解锁，使用独立的短超时背景上下文。
	ctx, cancel := context.WithTimeout(context.Background(), cleanupTimeout)
	defer cancel()
	if locked {
		var unlocked bool
		err := conn.QueryRow(ctx, "SELECT pg_advisory_unlock($1)", migrationLockKey).Scan(&unlocked)
		if err == nil && unlocked {
			conn.Release()
			return nil
		}
		if err != nil {
			retErr = fmt.Errorf("migrate: release advisory lock: %w", err)
		} else {
			retErr = errors.New("migrate: advisory lock was not held during cleanup")
		}
	}
	// [13] 获取锁失败时状态可能不明；解锁失败也不得让潜在持锁连接返回连接池。
	raw := conn.Hijack()
	if err := raw.Close(ctx); err != nil {
		retErr = errors.Join(retErr, fmt.Errorf("migrate: close discarded connection: %w", err))
	}
	return retErr
}
