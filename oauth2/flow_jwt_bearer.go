package oauth2

import (
	"context"
	"crypto/rsa"
	"fmt"
	"strings"
	"time"

	"github.com/ory/hydra/jwk"

	"github.com/dgrijalva/jwt-go"
	"github.com/ory/fosite"
	"github.com/ory/fosite/compose"
	"github.com/ory/fosite/handler/oauth2"
	"github.com/ory/fosite/handler/openid"
	"github.com/pkg/errors"
)

// JWT bearer grant type mark. According to the latest https://tools.ietf.org/html/rfc7523
const jwtBearerGrantType = "urn:ietf:params:oauth:grant-type:jwt-bearer"

// JWTBearerGrantFactory function for creating handler for JWT Bearer Grant
func JWTBearerGrantFactory(config *compose.Config, storage interface{}, strategy interface{}) interface{} {
	return &JWTBearerGrantHandler{
		HandleHelper: &oauth2.HandleHelper{
			AccessTokenStrategy: strategy.(oauth2.AccessTokenStrategy),
			AccessTokenStorage:  storage.(oauth2.AccessTokenStorage),
			AccessTokenLifespan: config.GetAccessTokenLifespan(),
		},
		ScopeStrategy: fosite.HierarchicScopeStrategy,
		KeyManager:    storage.(jwk.Manager),
		Audience:      storage.(CommonStore).ClusterURL,
	}
}

// JWTBearerGrantHandler handles JWT bearer flow
type JWTBearerGrantHandler struct {
	*oauth2.HandleHelper
	ScopeStrategy fosite.ScopeStrategy
	KeyManager    jwk.Manager
	Audience      string
}

// HandleTokenEndpointRequest implements https://tools.ietf.org/html/rfc7523#section-3
func (c *JWTBearerGrantHandler) HandleTokenEndpointRequest(ctx context.Context, request fosite.AccessRequester) error {
	// grant_type REQUIRED.
	// Value MUST be set to "urn:ietf:params:oauth:client-assertion-type:jwt-bearer".
	if !request.GetGrantTypes().Exact(jwtBearerGrantType) {
		return errors.WithStack(fosite.ErrUnknownRequest)
	}

	client := request.GetClient()

	if !client.GetGrantTypes().Has(jwtBearerGrantType) {
		return errors.Wrap(fosite.ErrInvalidGrant,
			fmt.Sprintf("The client is not allowed to use grant type %s", jwtBearerGrantType))
	}

	for _, scope := range request.GetRequestedScopes() {
		if !c.ScopeStrategy(client.GetScopes(), scope) {
			return errors.Wrap(fosite.ErrInvalidScope, fmt.Sprintf("The client is not allowed to request scope %s", scope))
		}
	}

	// assertion REQUIRED.
	// Value MUST be set to JWT string value.
	jwtToken := request.GetRequestForm().Get("assertion")
	if jwtToken == "" {
		return errors.Wrap(fosite.ErrInvalidRequest, "Field 'assertion' is missing")
	}

	token, err := jwt.Parse(jwtToken, func(token *jwt.Token) (interface{}, error) {
		// We stick to this option: https://tools.ietf.org/html/rfc7515#section-4.1.4
		keyID, _ := token.Header["kid"].(string)
		if keyID == "" {
			return nil, errors.Wrap(fosite.ErrInvalidTokenFormat,
				"Your key-set id should be present in 'kid' of the JOSE header")
		}
		switch token.Method.(type) {
		case *jwt.SigningMethodRSA, *jwt.SigningMethodECDSA:
			ks, err := c.KeyManager.GetKey(keyID, "public")
			if err != nil {
				return nil, errors.Wrap(fosite.ErrServerError, err.Error())
			}
			rsaKey, ok := jwk.First(ks.Keys).Key.(*rsa.PublicKey)
			if !ok {
				return nil, errors.Wrap(fosite.ErrServerError, "Could not convert to RSA Public Key")
			}
			return rsaKey, nil
		default:
			return nil, errors.Wrap(
				fosite.ErrInvalidTokenFormat,
				fmt.Sprintf("Unexpected signing method: '%v'. We support only RSA, ECDSA", token.Header["alg"]))
		}
	})

	if err != nil {
		return errors.Wrap(fosite.ErrInactiveToken, err.Error())
	}
	if !token.Valid {
		return errors.Wrap(fosite.ErrTokenSignatureMismatch, "Your JWT token failed to pass a signature validation")
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return errors.Wrap(fosite.ErrInvalidTokenFormat, "JWT claims were not found or are malformed")
	}

	// For https://tools.ietf.org/html/rfc7523#section-3.1
	// Additionally we check if it is a client ID.
	// Checking client ID here is somewhat redundant since it was set earlier by the 'iss' field of this JWT,
	// but let's leave it here to keep all checks in one place.
	if !claims.VerifyIssuer(client.GetID(), true) {
		return errors.Wrap(fosite.ErrTokenClaim, "Issuer (iss) claim should be present and should be your client ID")
	}
	// For https://tools.ietf.org/html/rfc7523#section-3.2
	if claims["sub"] == "" {
		errors.Wrap(fosite.ErrTokenClaim, "Subject (sub) claim should be present")
	}
	// For https://tools.ietf.org/html/rfc7523#section-3.3
	if !claims.VerifyAudience(strings.Trim(c.Audience, "/")+"/oauth2/token", true) {
		errors.Wrap(fosite.ErrTokenClaim, "Audience (aud) claim should be present")
	}
	// For https://tools.ietf.org/html/rfc7523#section-3.3
	if !claims.VerifyExpiresAt(time.Now().Unix(), true) {
		errors.Wrap(fosite.ErrTokenExpired, "Expires (exp) claim should be present. JWT should not be expired")
	}
	// This is a custom claim for detecting tenant ID.
	if claims["tnt"] == "" {
		errors.Wrap(fosite.ErrTokenClaim, "Tenant (tnt) claim should be present and be a tenant identifier")
	}

	// The client MUST authenticate with the authorization server as described in Section 3.2.1.
	// in https://tools.ietf.org/html/rfc6749#section-3.2.1
	if client.IsPublic() {
		return errors.Wrap(fosite.ErrInvalidGrant,
			fmt.Sprintf("The client is public and thus not allowed to use grant type '%s'", jwtBearerGrantType))
	}

	session, ok := request.GetSession().(*Session)
	if !ok {
		return errors.WithStack(openid.ErrInvalidSession)
	}

	session.SetExpiresAt(fosite.AccessToken, time.Now().Add(c.AccessTokenLifespan))
	session.Username = claims["sub"].(string)
	session.SetExtra("tenant", claims["tnt"])
	return nil
}

// PopulateTokenEndpointResponse implements https://tools.ietf.org/html/rfc7523#section-3
func (c *JWTBearerGrantHandler) PopulateTokenEndpointResponse(ctx context.Context, request fosite.AccessRequester, response fosite.AccessResponder) error {
	return nil
}
