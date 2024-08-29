package application

import (
	"context"
	"go-template/internal/auth/domain"
	"go-template/internal/auth/domain/cookiesession"
	"go-template/internal/auth/domain/jwt"
	"go-template/internal/shared/infrastructure/logger"
	"go-template/pkg/apperrors"
)

type Authenticator interface {
	JWTAuthenticate(token string) (*domain.AuthUserInfo, *apperrors.Error)
	CookieSessionAuthenticate(c context.Context, sessionId string) (*domain.AuthUserInfo, *apperrors.Error)
}

type authenticatorService struct {
	jwtService           *jwt.JWTService
	cookiesessionService *cookiesession.CookieSessionService
	logger               logger.Logger
}

func NewAuthenticatorService(
	jwtService *jwt.JWTService,
	cookiesessionService *cookiesession.CookieSessionService,
	logger logger.Logger,
) Authenticator {
	return &authenticatorService{
		jwtService:           jwtService,
		cookiesessionService: cookiesessionService,
		logger:               logger,
	}
}

func (s *authenticatorService) JWTAuthenticate(token string) (*domain.AuthUserInfo, *apperrors.Error) {
	authUserInfo, err := s.jwtService.Authenticate(token)
	if err != nil {
		s.logger.Error("Failed to authenticate token", err)
		return &domain.AuthUserInfo{}, apperrors.NewAuthorization("invalid token")
	}

	return authUserInfo, nil
}

func (s *authenticatorService) CookieSessionAuthenticate(ctx context.Context, sessionId string) (*domain.AuthUserInfo, *apperrors.Error) {
	authUserInfo, err := s.cookiesessionService.Authenticate(ctx, sessionId)
	if err != nil {
		s.logger.Error("Failed to authenticate session", err)
		return &domain.AuthUserInfo{}, apperrors.NewAuthorization("invalid session")
	}

	return authUserInfo, nil
}
