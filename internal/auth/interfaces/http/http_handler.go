package http

import (
	"go-template/internal/auth/application"
	"go-template/internal/auth/interfaces/dto"
	"net/http"

	_ "go-template/docs"

	"github.com/gin-gonic/gin"
)

type AuthHandler struct {
	authService application.AuthApplicationService
}

func NewAuthHandler(authService application.AuthApplicationService) *AuthHandler {
	return &AuthHandler{authService: authService}
}

type RegisterInput struct {
	Email    string `json:"email" example:"user@example.com"`
	Username string `json:"username" example:"johndoe"`
	Password string `json:"password" example:"secretpassword"`
}

// @Summary Register a new user
// @Description Create a new user account
// @Tags auth
// @Accept json
// @Produce json
// @Param input body RegisterInput true "User registration details"
// @Success 201 {object} dto.UserResponse
// @Router /api/v1/register [post]
func (h *AuthHandler) Register(c *gin.Context) {
	var input RegisterInput

	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	user, err := h.authService.Register(c.Request.Context(), input.Email, input.Username, input.Password)
	if err != nil {
		c.JSON(err.Status(), gin.H{"error": err.Message})
		return
	}

	c.JSON(http.StatusCreated, dto.NewUserResponse(user))
}

// @Summary Login
// @Description Login to the application
// @Tags auth
// @Accept json
// @Produce json
// @Param input body dto.LoginInput true "User login details"
// @Success 200 {object} dto.LoginResponse
// @Router /api/v1/login [post]
func (h *AuthHandler) Login(c *gin.Context) {
	var input dto.LoginInput

	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// ---- Login with JWT ----
	user, token, err := h.authService.Login(c.Request.Context(), input.Email, input.Username, input.Password)
	if err != nil {
		c.JSON(err.Status(), gin.H{"error": err.Message})
		return
	}
	// ---- [END] Login with JWT ----

	// ---- Login with Cookie Session ----
	user, sessionId, err := h.authService.Login(c.Request.Context(), input.Email, input.Username, input.Password)
	if err != nil {
		c.JSON(err.Status(), gin.H{"error": err.Message})
		return
	}

	// set cookie
	c.SetCookie("session_id", sessionId, 60*30, "/", c.Request.URL.Hostname(), false, true)
	// ---- [END] Login with Cookie Session ----

	c.JSON(http.StatusOK, gin.H{
		"user":  dto.NewUserResponse(user),
		"token": token,
	})
}

// @Summary Logout
// @Description Logout from the application
// @Tags auth
// @Security ApiKeyAuth
// @Success 204
// @Router /api/v1/logout [post]
func (h *AuthHandler) Logout(c *gin.Context) {
	sessionId, err := c.Cookie("session_id")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "session_id cookie not found"})
		return
	}

	err = h.authService.Logout(c.Request.Context(), sessionId)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.SetCookie("session_id", "", -1, "/", c.Request.URL.Hostname(), false, true)

	c.JSON(http.StatusNoContent, nil)
}
