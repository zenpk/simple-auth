package main

import (
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	"time"
)

const (
	jwtSecret = "6be34f79-0343-4f8a-a75e-5224c6001a41"
	tokenAge  = 8760 // hours
)

type MyCustomClaims struct {
	jwt.RegisteredClaims
	Id uint64 `json:"id"`
}

// genToken generate JWT token
func genToken(claims *MyCustomClaims) (string, error) {
	age := time.Duration(tokenAge) * time.Hour
	customClaims := MyCustomClaims{
		jwt.RegisteredClaims{
			// fixed dates can also be used for the NumericDate
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(age)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
		},
		claims.Id,
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, customClaims)
	signedToken, err := token.SignedString([]byte(jwtSecret))
	if err != nil {
		return "", err
	}
	return signedToken, nil
}

// parseToken extract infos from the token
func parseToken(tokenString string) (*MyCustomClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &MyCustomClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(jwtSecret), nil
	})
	if claims, ok := token.Claims.(*MyCustomClaims); ok && token.Valid {
		return claims, nil
	} else {
		return nil, err
	}
}
