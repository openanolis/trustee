package config

import (
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

// Config represents the application configuration
type Config struct {
	Server   ServerConfig   `mapstructure:"server"`
	KBS      ServiceConfig  `mapstructure:"kbs"`
	RVPS     RVPSConfig     `mapstructure:"rvps"`
	Database DatabaseConfig `mapstructure:"database"`
	Logging  LoggingConfig  `mapstructure:"logging"`
}

// ServerConfig holds the gateway server configuration
type ServerConfig struct {
	Host string `mapstructure:"host"`
	Port int    `mapstructure:"port"`
}

// ServiceConfig holds configuration for the upstream services (KBS)
type ServiceConfig struct {
	URL string `mapstructure:"url"`
}

// RVPSConfig holds configuration for the RVPS service
type RVPSConfig struct {
	GRPCAddr   string `mapstructure:"grpc_addr"`
}

// DatabaseConfig holds database configuration
type DatabaseConfig struct {
	Type string `mapstructure:"type"`
	Path string `mapstructure:"path"`
}

// LoggingConfig holds logging configuration
type LoggingConfig struct {
	Level string `mapstructure:"level"`
}

// LoadConfig loads the application configuration from file
func LoadConfig(configPath string) (*Config, error) {
	viper.SetConfigFile(configPath)

	// Set defaults
	viper.SetDefault("server.host", "0.0.0.0")
	viper.SetDefault("server.port", 8081)
	viper.SetDefault("kbs.url", "http://localhost:8080")
	viper.SetDefault("rvps.grpc_addr", "localhost:50003")
	viper.SetDefault("database.type", "sqlite")
	viper.SetDefault("database.path", "./trustee-gateway.db")
	viper.SetDefault("logging.level", "info")

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
