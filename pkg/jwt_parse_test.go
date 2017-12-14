package pkg_test

import (
	"testing"
	"time"

	"github.com/ory/hydra/pkg"

	"github.com/dgrijalva/jwt-go"
	"github.com/stretchr/testify/assert"
)

func TestJWTParseTimeWindowFieldAccessors(t *testing.T) {
	assert.Equal(t, time.Duration(0)*time.Second, pkg.GetJWTParseTimeWindow())

	pkg.SetJWTParseTimeWindow(10)
	assert.Equal(t, time.Duration(10)*time.Second, pkg.GetJWTParseTimeWindow())

	pkg.SetJWTParseTimeWindow(300)
	assert.Equal(t, time.Duration(300)*time.Second, pkg.GetJWTParseTimeWindow())

	pkg.SetJWTParseTimeWindow(0)
	assert.Equal(t, time.Duration(0)*time.Second, pkg.GetJWTParseTimeWindow())
}

func TestJWTParseUsingTimeWindow(t *testing.T) {
	secret := "foo"
	claims := jwt.MapClaims{
		"iss": "aaaa",
		"sub": "alice",
		"aud": "http://hydra-cluster.url",
	}
	keyFunc := func(token *jwt.Token) (interface{}, error) {
		return []byte(secret), nil
	}

	for k, c := range []struct {
		window        uint
		iat           int64
		exp           int64
		shouldSucceed bool
		description   string
	}{
		{
			description:   "window is not set. JWT is issued in the past",
			window:        0,
			iat:           time.Now().Add(-1 * time.Minute).Unix(),
			exp:           time.Now().Add(time.Hour * 24).Unix(),
			shouldSucceed: true,
		},
		{
			description:   "window is not set. JWT is issued in the future",
			window:        0,
			iat:           time.Now().Add(1 * time.Second).Unix(),
			exp:           time.Now().Add(time.Hour * 24).Unix(),
			shouldSucceed: false,
		},
		{
			description:   "window is not set. JWT is expired",
			window:        0,
			iat:           time.Now().Add(1 * time.Second).Unix(),
			exp:           time.Now().Add(time.Hour * -24).Unix(),
			shouldSucceed: false,
		},
		{
			description:   "window is the same as time unsync of JWT issued in the future",
			window:        1,
			iat:           time.Now().Add(1 * time.Second).Unix(),
			exp:           time.Now().Add(time.Hour * 24).Unix(),
			shouldSucceed: true,
		},
		{
			description:   "window is the same as time unsync of JWT issued in the past",
			window:        1,
			iat:           time.Now().Add(-1 * time.Second).Unix(),
			exp:           time.Now().Add(time.Hour * 24).Unix(),
			shouldSucceed: true,
		},
		{
			description:   "window is smaller than time unsync of JWT issued in the future",
			window:        3,
			iat:           time.Now().Add(15 * time.Second).Unix(),
			exp:           time.Now().Add(time.Hour * 24).Unix(),
			shouldSucceed: false,
		},
		{
			description:   "window is smaller than time unsync of JWT issued in the past",
			window:        3,
			iat:           time.Now().Add(-15 * time.Second).Unix(),
			exp:           time.Now().Add(time.Hour * 24).Unix(),
			shouldSucceed: true,
		},
		{
			description:   "window is bigger than time unsync of JWT issued in the future",
			window:        30,
			iat:           time.Now().Add(6 * time.Second).Unix(),
			exp:           time.Now().Add(time.Hour * 24).Unix(),
			shouldSucceed: true,
		},
		{
			description:   "window is bigger than time unsync of JWT issued in the past",
			window:        30,
			iat:           time.Now().Add(-6 * time.Second).Unix(),
			exp:           time.Now().Add(time.Hour * 24).Unix(),
			shouldSucceed: true,
		},
		{
			description:   "window is bigger than time unsync of JWT issued in the past, but smaller than token exp time",
			window:        30,
			iat:           time.Now().Add(-6 * time.Second).Unix(),
			exp:           time.Now().Add(35 * time.Second).Unix(),
			shouldSucceed: true,
		},
		{
			description:   "window is bigger than time unsync of JWT issued in the past, and bigger than token exp time",
			window:        2,
			iat:           time.Now().Add(-1 * time.Second).Unix(),
			exp:           time.Now().Add(1 * time.Second).Unix(),
			shouldSucceed: false,
		},
	} {
		pkg.SetJWTParseTimeWindow(c.window)
		claims["iat"] = c.iat
		claims["exp"] = c.exp

		_, err := pkg.JWTParseUsingTimeWindow(generateTestJWT(claims, secret), keyFunc)

		if c.shouldSucceed {
			assert.Nil(t, err, "Case (%d): %s", k, c.description)
		} else {
			assert.NotNil(t, err, "Case (%d): %s", k, c.description)
		}
	}
}

// generateTestJWT creates a valid test HMAC signed JWT with provided claims.
func generateTestJWT(claims jwt.MapClaims, secret string) string {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, _ := token.SignedString([]byte(secret))
	return tokenString
}
