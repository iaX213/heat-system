package jwt

import (
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

type JWTManager struct {
	secretKey       string
	accessTokenTTL  time.Duration
	refreshTokenTTL time.Duration
}

type Claims struct {
	UserID   string
	UserRole string
	jwt.RegisteredClaims
}

func NewJWTManager(secretKey string, accessTokenTTL time.Duration, refreshTokenTTL time.Duration) (*JWTManager, error) {
	return &JWTManager{
		secretKey:       secretKey,
		accessTokenTTL:  accessTokenTTL,
		refreshTokenTTL: refreshTokenTTL,
	}, nil
}

func (j *JWTManager) ParseJWT(tokenStr string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenStr, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return j.secretKey, nil
	})

	if err != nil {
		return nil, fmt.Errorf("invalid token: %w", err)
	}

	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("invalid or expired token")
	}
	return claims, nil
}

func (j *JWTManager) GenerateAccessToken(userID string, role string) (string, error) {
	expirationTime := time.Now().Add(j.accessTokenTTL)

	claims := &Claims{
		UserID:   userID,
		UserRole: role,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expirationTime),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	tokenString, err := token.SignedString(j.secretKey)
	if err != nil {
		return "", fmt.Errorf("access token generation: %w", err)
	}
	return tokenString, nil
}

func (j *JWTManager) GenerateRefreshToken(userID string, role string) (string, time.Time) {
	tokenString := uuid.NewString()
	expirationTime := time.Now().Add(j.refreshTokenTTL)

	return tokenString, expirationTime
}
