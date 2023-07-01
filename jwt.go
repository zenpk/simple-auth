package main

import (
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	"time"
)

const (
	jwtSecret = "6be34f79-0343-4f8a-a75e-5224c6001a41"
	tokenAge  = 1 // hours
)

type MyCustomClaims struct {
	jwt.RegisteredClaims
	Data string `json:"data"`
}

// GenBasicToken generate JWT token without data
func genBasicToken() (string, error) {
	claims := jwt.RegisteredClaims{
		// fixed dates can also be used for the NumericDate
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(tokenAge)),
		IssuedAt:  jwt.NewNumericDate(time.Now()),
		NotBefore: jwt.NewNumericDate(time.Now()),
	}
	return genToken(claims)
}

func genDataToken(data string, tokenAge time.Duration) (string, error) {
	age := time.Duration(tokenAge) * time.Hour
	customClaims := MyCustomClaims{
		jwt.RegisteredClaims{
			// fixed dates can also be used for the NumericDate
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(age)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
		},
		data,
	}
	return genToken(customClaims)
}

func genToken(claims jwt.Claims) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signedToken, err := token.SignedString([]byte(jwtSecret))
	if err != nil {
		return "", err
	}
	return signedToken, nil
}

// parseBasicToken parse token without additional info
func parseBasicToken(tokenString string) (*jwt.RegisteredClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &jwt.RegisteredClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(jwtSecret), nil
	})
	if claims, ok := token.Claims.(*jwt.RegisteredClaims); ok && token.Valid {
		return claims, nil
	} else {
		return nil, err
	}
}

// parseDataToken extract infos from the token
func parseDataToken(tokenString string) (*MyCustomClaims, error) {
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
