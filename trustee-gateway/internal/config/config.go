package config

import (
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

// Config represents the application configuration
type Config struct {
	Server                       ServerConfig                       `mapstructure:"server"`
	KBS                          ServiceConfig                      `mapstructure:"kbs"`
	AttestationService           ServiceConfig                      `mapstructure:"attestation_service"`
	RVPS                         RVPSConfig                         `mapstructure:"rvps"`
	Database                     DatabaseConfig                     `mapstructure:"database"`
	Logging                      LoggingConfig                      `mapstructure:"logging"`
	Audit                        AuditConfig                        `mapstructure:"audit"`
	AttestationAgentInstanceInfo AttestationAgentInstanceInfoConfig `mapstructure:"attestation_agent_instance_info"`
}

// ServerConfig holds the gateway server configuration
type ServerConfig struct {
	Host         string    `mapstructure:"host"`
	Port         int       `mapstructure:"port"`
	TLS          TLSConfig `mapstructure:"tls"`
	InsecureHTTP bool      `mapstructure:"insecure_http"`
}

// TLSConfig holds TLS configuration
type TLSConfig struct {
	CertFile string `mapstructure:"cert_file"`
	KeyFile  string `mapstructure:"key_file"`
}

// ServiceConfig holds configuration for the upstream services (KBS)
type ServiceConfig struct {
	URL          string `mapstructure:"url"`
	InsecureHTTP bool   `mapstructure:"insecure_http"`
	CACertFile   string `mapstructure:"ca_cert_file"`
}

// RVPSConfig holds configuration for the RVPS service
type RVPSConfig struct {
	GRPCAddr string `mapstructure:"grpc_addr"`
}

// DatabaseConfig holds database configuration
type DatabaseConfig struct {
	Type string `mapstructure:"type"` // "sqlite" or "mysql"

	// SQLite configuration
	Path                   string `mapstructure:"path"` // SQLite file path
	UseMemory              bool   `mapstructure:"use_memory"`
	BackupInterval         string `mapstructure:"backup_interval"`
	EnableBackupOnShutdown bool   `mapstructure:"enable_backup_on_shutdown"`

	// MySQL configuration using DSN (Data Source Name) URL
	// Format: user:password@tcp(host:port)/dbname?charset=utf8mb4&parseTime=True&loc=Local
	// Example: root:123456@tcp(localhost:3306)/trustee_gateway?charset=utf8mb4&parseTime=True&loc=Local
	DSN             string `mapstructure:"dsn"`
	MaxOpenConns    int    `mapstructure:"max_open_conns"`
	MaxIdleConns    int    `mapstructure:"max_idle_conns"`
	ConnMaxLifetime string `mapstructure:"conn_max_lifetime"`
}

// LoggingConfig holds logging configuration
type LoggingConfig struct {
	Level string `mapstructure:"level"`
}

// AttestationAgentInfoConfig holds configuration for attestation agent heartbeat
type AttestationAgentInstanceInfoConfig struct {
	HeartbeatTimeoutMinutes int `mapstructure:"heartbeat_timeout_minutes"`
}

// AuditConfig holds audit configuration
type AuditConfig struct {
	MaxRecords           int `mapstructure:"max_records"`
	RetentionDays        int `mapstructure:"retention_days"`
	CleanupIntervalHours int `mapstructure:"cleanup_interval_hours"`
}

// LoadConfig loads the application configuration from file
func LoadConfig(configPath string) (*Config, error) {
	viper.SetConfigFile(configPath)

	// Set defaults
	viper.SetDefault("server.host", "0.0.0.0")
	viper.SetDefault("server.port", 8081)
	viper.SetDefault("server.insecure_http", true)
	viper.SetDefault("kbs.url", "http://localhost:8080")
	viper.SetDefault("attestation_service.url", "http://localhost:50005")
	viper.SetDefault("rvps.grpc_addr", "localhost:50003")
	viper.SetDefault("database.type", "sqlite")
	viper.SetDefault("database.path", "./trustee-gateway.db")
	viper.SetDefault("database.use_memory", true)
	viper.SetDefault("database.backup_interval", "2m")
	viper.SetDefault("database.enable_backup_on_shutdown", true)
	// MySQL defaults (DSN format: user:password@tcp(host:port)/dbname?params)
	viper.SetDefault("database.dsn", "")
	viper.SetDefault("database.max_open_conns", 10)
	viper.SetDefault("database.max_idle_conns", 5)
	viper.SetDefault("database.conn_max_lifetime", "1h")
	viper.SetDefault("logging.level", "info")
	viper.SetDefault("audit.max_records", 1000)
	viper.SetDefault("audit.retention_days", 3)
	viper.SetDefault("audit.cleanup_interval_hours", 24)
	viper.SetDefault("attestation_agent_instance_info.heartbeat_timeout_minutes", 10)

	if err := viper.ReadInConfig(); err != nil {
		logrus.Warnf("Failed to read config file: %v. Using default values.", err)
	}

	var config Config
	if err := viper.Unmarshal(&config); err != nil {
		return nil, err
	}

	return &config, nil
}

// SetupLogging configures the logger based on the config
func SetupLogging(config *Config) {
	level, err := logrus.ParseLevel(config.Logging.Level)
	if err != nil {
		logrus.Warnf("Invalid log level '%s', using 'info'", config.Logging.Level)
		level = logrus.InfoLevel
	}
	logrus.SetLevel(level)
	logrus.SetFormatter(&logrus.JSONFormatter{})
}
