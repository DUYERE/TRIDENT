package db

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io/fs"
	"reflect"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestLoadMigrationsSortAndChecksum(t *testing.T) {
	// [01] 使用内存文件系统验证排序、完整文件名版本及原始字节校验和，无需数据库。
	files := fstest.MapFS{
		"migrations/020_later.sql":  {Data: []byte("SELECT 2;\r\n")},
		"migrations/001_first.sql":  {Data: []byte("abc")},
		"migrations/010_middle.sql": {Data: []byte("SELECT 1;\n")},
		"migrations/README.txt":     {Data: []byte("ignored")},
		"migrations/sub/999.sql":    {Data: []byte("SELECT 999;")},
		"migrations/directory.sql":  {Mode: fs.ModeDir},
	}
	got, err := loadMigrations(files)
	if err != nil {
		t.Fatal(err)
	}
	versions := make([]string, len(got))
	for i, m := range got {
		versions[i] = m.version
		original := files["migrations/"+m.version].Data
		if m.sql != string(original) {
			t.Errorf("migration %q SQL bytes changed", m.version)
		}
		sum := sha256.Sum256(original)
		if want := hex.EncodeToString(sum[:]); m.checksum != want {
			t.Errorf("migration %q checksum = %q, want %q", m.version, m.checksum, want)
		}
	}
	wantVersions := []string{"001_first.sql", "010_middle.sql", "020_later.sql"}
	if !reflect.DeepEqual(versions, wantVersions) {
		t.Fatalf("versions = %v, want %v", versions, wantVersions)
	}
	if want := "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"; got[0].checksum != want {
		t.Errorf("known SHA-256 = %q, want %q", got[0].checksum, want)
	}
}

func TestLoadMigrationsPreservesByteDifferences(t *testing.T) {
	// [02] 换行或末尾空白变化也必须改变校验和，不能静默正规化。
	bodies := []string{"SELECT 1;\n", "SELECT 1;\r\n", "SELECT 1; \n", "SELECT 1;"}
	seen := make(map[string]bool)
	for _, body := range bodies {
		got, err := loadMigrations(fstest.MapFS{
			"migrations/001.sql": {Data: []byte(body)},
		})
		if err != nil {
			t.Fatal(err)
		}
		if seen[got[0].checksum] {
			t.Fatalf("distinct raw bytes produced a duplicate checksum: %q", body)
		}
		seen[got[0].checksum] = true
	}
}

func TestLoadMigrationsErrors(t *testing.T) {
	tests := []struct {
		name    string
		files   fs.FS
		want    string
		wantErr error
	}{
		{
			name:    "missing directory",
			files:   fstest.MapFS{},
			want:    "list embedded migrations",
			wantErr: fs.ErrNotExist,
		},
		{
			name:  "empty directory",
			files: fstest.MapFS{"migrations": {Mode: fs.ModeDir}},
			want:  "no embedded SQL migrations",
		},
		{
			name:  "no SQL files",
			files: fstest.MapFS{"migrations/readme.txt": {Data: []byte("ignore")}},
			want:  "no embedded SQL migrations",
		},
		{
			name:  "empty SQL",
			files: fstest.MapFS{"migrations/001.sql": {}},
			want:  `migration "001.sql" is empty`,
		},
		{
			name:  "whitespace SQL",
			files: fstest.MapFS{"migrations/001.sql": {Data: []byte(" \n\t\r\n")}},
			want:  `migration "001.sql" is empty`,
		},
		{
			name: "unreadable SQL",
			files: failingMigrationFS{
				FS:       fstest.MapFS{"migrations/001.sql": {Data: []byte("SELECT 1;")}},
				failPath: "migrations/001.sql",
			},
			want:    `read migration "001.sql"`,
			wantErr: fs.ErrPermission,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := loadMigrations(tt.files)
			assertErrorContains(t, err, tt.want)
			if tt.wantErr != nil && !errors.Is(err, tt.wantErr) {
				t.Errorf("error = %v, want wrapped %v", err, tt.wantErr)
			}
		})
	}
}

type failingMigrationFS struct {
	fs.FS
	failPath string
}

func (f failingMigrationFS) Open(name string) (fs.File, error) {
	if name == f.failPath {
		return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrPermission}
	}
	return f.FS.Open(name)
}

func TestEmbeddedMigrationManifest(t *testing.T) {
	// [03] 验证实际 go:embed 清单可读，不依赖首批迁移具体数量及业务 SQL 内容。
	got, err := loadMigrations(migrationFiles)
	if err != nil {
		t.Fatal(err)
	}
	for i, m := range got {
		if i > 0 && got[i-1].version >= m.version {
			t.Errorf("manifest is not strictly sorted at %q", m.version)
		}
		if len(m.checksum) != 64 {
			t.Errorf("migration %q checksum length = %d, want 64", m.version, len(m.checksum))
		}
		if _, err := hex.DecodeString(m.checksum); err != nil {
			t.Errorf("migration %q invalid SHA-256: %v", m.version, err)
		}
	}
}

func TestValidateHistory(t *testing.T) {
	// [04] 迁移允许缺失待应用版本；只读检查要求全部应用，两者均拒绝未知版本与篡改。
	manifest := []migration{
		{version: "001.sql", checksum: "first"},
		{version: "002.sql", checksum: "second"},
	}
	tests := []struct {
		name       string
		applied    map[string]string
		requireAll bool
		want       string
	}{
		{name: "fresh migrate", applied: nil},
		{name: "partial migrate", applied: map[string]string{"001.sql": "first"}},
		{name: "complete migrate", applied: map[string]string{"001.sql": "first", "002.sql": "second"}},
		{name: "complete check", applied: map[string]string{"001.sql": "first", "002.sql": "second"}, requireAll: true},
		{name: "fresh check", requireAll: true, want: `migration "001.sql" is not applied`},
		{name: "partial check", applied: map[string]string{"001.sql": "first"}, requireAll: true, want: `migration "002.sql" is not applied`},
		{name: "modified migrate", applied: map[string]string{"001.sql": "tampered"}, want: `migration "001.sql" checksum mismatch`},
		{name: "modified check", applied: map[string]string{"001.sql": "tampered"}, requireAll: true, want: `migration "001.sql" checksum mismatch`},
		{name: "unknown migrate", applied: map[string]string{"999.sql": "unknown"}, want: `unknown migration "999.sql"`},
		{name: "unknown check", applied: map[string]string{"999.sql": "unknown"}, requireAll: true, want: `unknown migration "999.sql"`},
		{name: "empty checksum", applied: map[string]string{"001.sql": ""}, want: "checksum mismatch"},
		{name: "deterministic error", applied: map[string]string{"999.sql": "unknown", "998.sql": "unknown"}, want: `unknown migration "998.sql"`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateHistory(manifest, tt.applied, tt.requireAll)
			if tt.want == "" {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			assertErrorContains(t, err, tt.want)
		})
	}
}

func TestValidateActor(t *testing.T) {
	for _, actor := range []string{"", " ", "\t\r\n", "　 "} {
		t.Run("invalid_"+actor, func(t *testing.T) {
			assertErrorContains(t, validateActor(actor), "actor must not be empty")
			// [05] 即使 pool 为空也先拒绝无主体迁移，不尝试连接数据库。
			assertErrorContains(t, Migrate(context.Background(), nil, actor), "actor must not be empty")
		})
	}
	for _, actor := range []string{"admin", "local-cli:operator", "安全管理员", " actor "} {
		if err := validateActor(actor); err != nil {
			t.Errorf("valid actor %q: %v", actor, err)
		}
	}
}

func TestNilPool(t *testing.T) {
	assertErrorContains(t, Migrate(context.Background(), nil, "operator"), "pool is nil")
	assertErrorContains(t, Check(context.Background(), nil), "pool is nil")
}

func TestCanceledContextWithoutDatabase(t *testing.T) {
	// [06] pool 懒连接且预先取消上下文，验证未连接错误透传，无需运行 PostgreSQL。
	config, err := pgxpool.ParseConfig("postgres://test:test@127.0.0.1:1/test?sslmode=disable")
	if err != nil {
		t.Fatal(err)
	}
	config.MinConns = 0
	config.MinIdleConns = 0
	pool, err := pgxpool.NewWithConfig(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for _, run := range []struct {
		name string
		call func() error
	}{
		{name: "Migrate", call: func() error { return Migrate(ctx, pool, "operator") }},
		{name: "Check", call: func() error { return Check(ctx, pool) }},
	} {
		t.Run(run.name, func(t *testing.T) {
			if err := run.call(); !errors.Is(err, context.Canceled) {
				t.Fatalf("error = %v, want wrapped context.Canceled", err)
			}
		})
	}
}

func assertErrorContains(t *testing.T, err error, want string) {
	t.Helper()
	if err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("error = %v, want substring %q", err, want)
	}
}
