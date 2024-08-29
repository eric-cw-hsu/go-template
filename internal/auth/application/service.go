package application

import (
	"context"
	"go-template/internal/auth/domain"
	"go-template/internal/auth/domain/cookiesession"
	"go-template/internal/auth/domain/jwt"
	"go-template/internal/shared/infrastructure/logger"
)

type AuthApplicationService interface {
	Register(ctx context.Context, email, username, password string) (*domain.AuthUser, error)
	Login(ctx context.Context, email, username, password string) (*domain.AuthUser, string, error)
	Logout(ctx context.Context, sessionId string) error
}

type authApplicationService struct {
	authService          domain.AuthService
	jwtService           *jwt.JWTService
	cookieSessionService *cookiesession.CookieSessionService
	logger               logger.Logger
}

func NewAuthApplicationService(
	authService domain.AuthService,
	jwtService *jwt.JWTService,
	cookieSessionService *cookiesession.CookieSessionService,
	logger logger.Logger,
) AuthApplicationService {
	return &authApplicationService{
		authService:          authService,
		jwtService:           jwtService,
		cookieSessionService: cookieSessionService,
		logger:               logger,
	}
}

func (s *authApplicationService) Register(ctx context.Context, email, username, password string) (*domain.AuthUser, error) {
	// 1. check if user already exists
	exists, err := s.authService.CheckUserExists(ctx, email, username)
	if err != nil {
		return nil, err
	}

	if exists {
		return nil, domain.ErrUserAlreadyExists
	}

	// 2. create user
	return s.authService.CreateUser(ctx, email, username, password)
}

func (s *authApplicationService) Login(ctx context.Context, email, username, password string) (*domain.AuthUser, string, error) {
	return s.loginWithJWT(ctx, email, username, password)

	// or
	// return s.loginWithCookieSession(ctx, email, username, password)
}

func (s *authApplicationService) loginWithJWT(ctx context.Context, email, username, password string) (*domain.AuthUser, string, error) {
	// 1. check username, email, password in the database
	user, err := s.authService.AuthenticateUser(ctx, email, username, password)
	if err != nil {
		return nil, "", err
	}

	authUserInfo := domain.NewAuthUserInfo(user.ID, user.Email, user.Username, user.Role)

	// 2. generate jwt token
	token, err := s.jwtService.GenerateToken(authUserInfo)
	if err != nil {
		return nil, "", err
	}

	// 3. update last login
	user.UpdateLastLogin()

	return user, token, nil
}

func (s *authApplicationService) loginWithCookieSession(ctx context.Context, email, username, password string) (*domain.AuthUser, string, error) {
	// 1. check username, email, password in the database
	user, err := s.authService.AuthenticateUser(ctx, email, username, password)
	if err != nil {
		return nil, "", err
	}

	authUserInfo := domain.NewAuthUserInfo(user.ID, user.Email, user.Username, user.Role)

	// 2. create session
	sessionId, err := s.cookieSessionService.CreateSession(ctx, authUserInfo)
	if err != nil {
		return nil, "", err
	}

	user.UpdateLastLogin()

	return user, sessionId, nil
}

// This method only available for cookie-session authentication
func (s *authApplicationService) Logout(ctx context.Context, sessionId string) error {
	// 1. remove sessionId from redis
	err := s.cookieSessionService.DeleteSession(ctx, sessionId)
	if err != nil {
		s.logger.Error("Failed to logout", err)
		return err
	}

	return nil
}
