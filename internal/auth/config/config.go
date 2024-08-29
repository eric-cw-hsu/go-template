package config

import "go-template/internal/auth/domain/cookiesession"

type AuthConfig struct {
	Auth struct {
		JWTSecret       string `mapstructure:"jwt_secret"`
		TokenExpiration int    `mapstructure:"token_expiration"`

		CookieSession cookiesession.CookieSessionConfig
	} `mapstructure:"auth"`
}
