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
		KeyManager:    storage.(CommonStore).KeyManager,
		Audience:      strings.Trim(storage.(CommonStore).ClusterURL, "/") + "/oauth2/token",
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
			return nil, fmt.Errorf("your key-set ID should be present in 'kid' of the JOSE header")
		}
		switch token.Method.(type) {
		case *jwt.SigningMethodRSA, *jwt.SigningMethodECDSA:
			ks, err := c.KeyManager.GetKey(keyID, "public")
			if err != nil {
				return nil, err
			}
			rsaKey, ok := jwk.First(ks.Keys).Key.(*rsa.PublicKey)
			if !ok {
				return nil, fmt.Errorf("could not convert to RSA Public Key")
			}
			return rsaKey, nil
		default:
			return nil, fmt.Errorf("unexpected signing method: '%v'. We support only RSA, ECDSA", token.Header["alg"])
		}
	})

	if err != nil {
		// Catch possible jwt.Parse errors.
		if e, ok := errors.Cause(err).(*jwt.ValidationError); ok {
			switch e.Errors {
			case jwt.ValidationErrorUnverifiable, jwt.ValidationErrorSignatureInvalid:
				return errors.Wrap(fosite.ErrTokenSignatureMismatch, err.Error())
			case jwt.ValidationErrorExpired:
				return errors.Wrap(fosite.ErrTokenExpired, err.Error())
			case jwt.ValidationErrorIssuedAt:
				return errors.Wrap(fosite.ErrInactiveToken, err.Error())
			default:
				return errors.Wrap(fosite.ErrInvalidTokenFormat, err.Error())
			}
		}
		// It means we have some unknown error.
		return errors.Wrap(fosite.ErrServerError, err.Error())
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return errors.Wrap(fosite.ErrInvalidTokenFormat, "JWT claims were not found or are malformed")
	}

	// For https://tools.ietf.org/html/rfc7523#section-3.1
	// We check that client ID obtained from the Basic auth is what was stated as 'iss' in JWT.
	// Otherwise it can be a client ID forgery attempt.
	if !claims.VerifyIssuer(client.GetID(), true) {
		return errors.Wrap(fosite.ErrTokenClaim, "Issuer (iss) claim should be present and should be your client ID")
	}
	// For https://tools.ietf.org/html/rfc7523#section-3.2
	if val, ok := claims["sub"].(string); !ok || val == "" {
		return errors.Wrap(fosite.ErrTokenClaim, "Subject (sub) claim should be a nonempty string")
	}
	// For https://tools.ietf.org/html/rfc7523#section-3.3
	if !claims.VerifyAudience(c.Audience, true) {
		return errors.Wrap(fosite.ErrTokenClaim, "Audience (aud) is invalid or missing")
	}
	// For https://tools.ietf.org/html/rfc7523#section-3.3
	// Actually jwt.Parse already checks exp value, but it does not require it to be present, so re-checking it.
	if _, ok := claims["exp"]; !ok {
		return errors.Wrap(fosite.ErrTokenClaim, "Expires (exp) claim should be present")
	}
	// Actually jwt.Parse already checks iat value, but it does not require it to be present, so re-checking it.
	if _, ok := claims["iat"]; !ok {
		return errors.Wrap(fosite.ErrTokenClaim, "Issued at (iat) claim should be present")
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
	session.Subject = claims["sub"].(string)
	// Use custom claim for detecting tenant ID.
	if val, ok := claims["tnt"]; ok && val != "" {
		session.SetExtra("tenant", val)
	}
	return nil
}

// PopulateTokenEndpointResponse implements https://tools.ietf.org/html/rfc6749#section-4.4.3
func (c *JWTBearerGrantHandler) PopulateTokenEndpointResponse(ctx context.Context, request fosite.AccessRequester, response fosite.AccessResponder) error {
	if !request.GetGrantTypes().Exact(jwtBearerGrantType) {
		return errors.WithStack(fosite.ErrUnknownRequest)
	}

	if !request.GetClient().GetGrantTypes().Has(jwtBearerGrantType) {
		return errors.Wrap(fosite.ErrInvalidGrant, fmt.Sprintf("The client is not allowed to use grant type %s", jwtBearerGrantType))
	}

	return c.IssueAccessToken(ctx, request, response)
}
