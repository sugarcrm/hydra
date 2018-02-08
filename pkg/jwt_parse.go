package pkg

import (
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/pkg/errors"
)

// timeWindow represents "+/-" time window in seconds for parsing time specific JWT claims
var timeWindow time.Duration

// SetJWTParseTimeWindow sets timeWindow value
func SetJWTParseTimeWindow(window uint) {
	timeWindow = time.Duration(window) * time.Second
}

// GetJWTParseTimeWindow get timeWindow value
func GetJWTParseTimeWindow() time.Duration {
	return timeWindow
}

// JWTParseUsingTimeWindow is a wrapper for jwt.Parse() that uses "+/-" time window
// for parsing time specific JWT claims. It may take several attempts if one of the attempts fails.
func JWTParseUsingTimeWindow(tokenString string, keyFunc jwt.Keyfunc) (*jwt.Token, error) {
	return parseJWT(tokenString, jwt.MapClaims{}, keyFunc)
}

// JWTParseWithClaimsUsingTimeWindow is a wrapper for jwt.JWTParseWithClaims() that uses "+/-" time window
// for parsing time specific JWT claims. It may take several attempts if one of the attempts fails.
func JWTParseWithClaimsUsingTimeWindow(tokenString string, claims jwt.Claims, keyFunc jwt.Keyfunc) (*jwt.Token, error) {
	return parseJWT(tokenString, claims, keyFunc)
}

// parseJWT is internal function that does the actual JWT parsing regarding time window
func parseJWT(tokenString string, claims jwt.Claims, keyFunc jwt.Keyfunc) (*jwt.Token, error) {
	var token *jwt.Token
	var err error

	token, err = jwt.ParseWithClaims(tokenString, claims, keyFunc)

	// Maybe we need a second try with time window
	if err != nil && timeWindow != 0 {
		if e, ok := errors.Cause(err).(*jwt.ValidationError); ok {
			switch e.Errors {
			// case jwt.ValidationErrorIssuedAt, jwt.ValidationErrorExpired, jwt.ValidationErrorNotValidYet:
			case jwt.ValidationErrorIssuedAt:
				if token.Claims.(jwt.MapClaims).VerifyIssuedAt(time.Now().Add(timeWindow).Unix(), true) {
					e.Errors &^= jwt.ValidationErrorIssuedAt
				}
			case jwt.ValidationErrorExpired:
				if token.Claims.(jwt.MapClaims).VerifyExpiresAt(time.Now().Add(-timeWindow).Unix(), true) {
					e.Errors &^= jwt.ValidationErrorExpired
				}
			case jwt.ValidationErrorNotValidYet:
				if token.Claims.(jwt.MapClaims).VerifyNotBefore(time.Now().Add(timeWindow).Unix(), true) {
					e.Errors &^= jwt.ValidationErrorNotValidYet
				}
			}
		}
		if errors.Cause(err).(*jwt.ValidationError).Errors == 0 {
			err = nil
			token.Valid = true
		}
	}

	return token, err
}
