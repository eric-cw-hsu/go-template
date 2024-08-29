package cookiesession

import (
	"context"
	"go-template/internal/auth/domain"
	"go-template/internal/shared/infrastructure/logger"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/google/uuid"
)

type CookieSessionService struct {
	redisClient *redis.Client
	config      *CookieSessionConfig
	logger      logger.Logger
}

func NewCookieSessionService(redisClient *redis.Client, cookieSessionConfig *CookieSessionConfig, logger logger.Logger) *CookieSessionService {
	return &CookieSessionService{
		redisClient: redisClient,
		config:      cookieSessionConfig,
		logger:      logger,
	}
}

// CreateSession creates a new session in Redis
// with the given authUserInfo and returns the session ID
func (service *CookieSessionService) CreateSession(c context.Context, authUserInfo domain.AuthUserInfo) (string, error) {
	// create session
	sessionId := uuid.New().String()

	err := service.redisClient.Set(c, sessionId, authUserInfo, (time.Second * time.Duration(service.config.MaxAge))).Err()
	if err != nil {
		service.logger.Error("Failed to create session", err)
		return "", err
	}

	return sessionId, nil
}

func (service *CookieSessionService) Authenticate(c context.Context, sessionId string) (domain.AuthUserInfo, error) {
	value, err := service.redisClient.Get(c, sessionId).Result()
	if err != nil {
		service.logger.Error("Failed to authenticate session", err)
		return domain.AuthUserInfo{}, err
	}

	var authUserInfo domain.AuthUserInfo
	err = authUserInfo.UnmarshalBinary([]byte(value))
	if err != nil {
		service.logger.Error("Failed to unmarshal auth user info", err)
		return domain.AuthUserInfo{}, err
	}

	return authUserInfo, nil
}

func (service *CookieSessionService) DeleteSession(c context.Context, sessionId string) error {
	err := service.redisClient.Del(c, sessionId).Err()
	if err != nil {
		service.logger.Error("Failed to delete session", err)
		return err
	}

	return nil
}
