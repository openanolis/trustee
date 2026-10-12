package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
)

func writeConfig(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
	return path
}

func TestRequireSharedRejectsSQLite(t *testing.T) {
	viper.Reset()
	t.Cleanup(viper.Reset)
	path := writeConfig(t, "database:\n  type: sqlite\n  require_shared: true\n")

	_, err := LoadConfig(path)
	require.ErrorContains(t, err, "requires database.type=mysql")
}

func TestDatabaseDSNComesFromEnvironment(t *testing.T) {
	viper.Reset()
	t.Cleanup(viper.Reset)
	t.Setenv("TRUSTEE_GATEWAY_DATABASE_DSN", "user:secret@tcp(mysql:3306)/trustee")
	path := writeConfig(t, "database:\n  type: mysql\n  require_shared: true\n")

	config, err := LoadConfig(path)
	require.NoError(t, err)
	require.Equal(t, "user:secret@tcp(mysql:3306)/trustee", config.Database.DSN)
}
