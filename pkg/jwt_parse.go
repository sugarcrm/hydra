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
	timeFuncOriginal := jwt.TimeFunc
	doRetry := func(err error) bool {
		// if window is not specified - no need to retry.
		if timeWindow == 0 {
			return false
		}
		if err != nil {
			if e, ok := errors.Cause(err).(*jwt.ValidationError); ok {
				switch e.Errors {
				case jwt.ValidationErrorIssuedAt, jwt.ValidationErrorExpired, jwt.ValidationErrorNotValidYet:
					return true
				}
			}
		}
		return false
	}
	doParse := func(window time.Duration) (*jwt.Token, error) {
		jwt.TimeFunc = func() time.Time {
			return time.Now().Add(window)
		}
		return jwt.ParseWithClaims(tokenString, claims, keyFunc)
	}

	// First try with "+" window
	token, err = doParse(timeWindow)

	// Maybe we need a second try with "-" window
	if doRetry(err) {
		token, err = doParse(-1 * timeWindow)
	}

	jwt.TimeFunc = timeFuncOriginal
	return token, err
}
