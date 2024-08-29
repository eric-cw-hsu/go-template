package config

import "go-template/internal/shared/infrastructure/redis"

type AppConfig struct {
	Name        string
	Environment string
	Server      ServerConfig
	Database    DatabaseConfig
	Redis       redis.RedisConfig
}

type ServerConfig struct {
	Port int
}

type DatabaseConfig struct {
	Host     string
	Port     int
	Username string
	Password string
	Name     string
}

var App AppConfig
