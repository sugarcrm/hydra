package oauth2

import (
	"crypto/rsa"
	"fmt"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/ory/hydra/internal/mocks"
	"github.com/ory/hydra/jwk"

	"github.com/dgrijalva/jwt-go"
	"github.com/golang/mock/gomock"
	"github.com/ory/fosite"
	"github.com/ory/fosite/handler/oauth2"
	"github.com/ory/fosite/handler/openid"
	"github.com/pkg/errors"
	"github.com/square/go-jose"
	"github.com/stretchr/testify/assert"
)

func TestJWTBearerFlow_HandleTokenEndpointRequest_Validation(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	strategy := internal.NewMockAccessTokenStrategy(ctrl)
	store := internal.NewMockAccessTokenStorage(ctrl)
	keyManager := internal.NewMockManager(ctrl)
	areq := internal.NewMockAccessRequester(ctrl)
	client := internal.NewMockClient(ctrl)

	h := JWTBearerGrantHandler{
		HandleHelper: &oauth2.HandleHelper{
			AccessTokenStrategy: strategy,
			AccessTokenStorage:  store,
			AccessTokenLifespan: time.Hour,
		},
		ScopeStrategy: fosite.HierarchicScopeStrategy,
		KeyManager:    keyManager,
		Audience:      "http://hydra-cluster.url/oauth2/token",
	}

	for k, c := range []struct {
		description    string
		mock           func()
		req            *http.Request
		expectErr      error
		expectErrorMsg string
	}{
		{
			description:    "should fail because request handler is not responsible for this grant type",
			expectErr:      fosite.ErrUnknownRequest,
			expectErrorMsg: "not responsible",
			mock: func() {
				areq.EXPECT().GetGrantTypes().Return(fosite.Arguments{""})
			},
		},
		{
			description:    "should fail because client is not assigned to this this grant type",
			expectErr:      fosite.ErrInvalidGrant,
			expectErrorMsg: "client is not allowed to use grant type " + jwtBearerGrantType,
			mock: func() {
				client.EXPECT().GetGrantTypes().Return(fosite.Arguments{""})

				areq.EXPECT().GetGrantTypes().Return(fosite.Arguments{jwtBearerGrantType})
				areq.EXPECT().GetClient().Return(client)
			},
		},
		{
			description:    "should fail because client is not assigned to this scope",
			expectErr:      fosite.ErrInvalidScope,
			expectErrorMsg: "client is not allowed to request scope foo-scope",
			mock: func() {
				client.EXPECT().GetGrantTypes().Return(fosite.Arguments{jwtBearerGrantType})
				client.EXPECT().GetScopes().Return(fosite.Arguments{"bar-scope"})
				areq.EXPECT().GetClient().Return(client)

				areq.EXPECT().GetGrantTypes().Return(fosite.Arguments{jwtBearerGrantType})
				areq.EXPECT().GetRequestedScopes().Return(fosite.Arguments{"foo-scope"})
			},
		},
		{
			description:    "should fail because field 'assertion' is missing in the request form data",
			expectErr:      fosite.ErrInvalidRequest,
			expectErrorMsg: "'assertion' is missing",
			mock: func() {
				client.EXPECT().GetGrantTypes().Return(fosite.Arguments{jwtBearerGrantType})
				client.EXPECT().GetScopes().Return(fosite.Arguments{"foo-scope"})
				areq.EXPECT().GetClient().Return(client)

				areq.EXPECT().GetGrantTypes().Return(fosite.Arguments{jwtBearerGrantType})
				areq.EXPECT().GetRequestedScopes().Return(fosite.Arguments{"foo-scope"})

				areq.EXPECT().GetRequestForm().Return(url.Values{})
			},
		},
		{
			description:    "should fail because 'assertion' field contains malformed JWT token",
			expectErr:      fosite.ErrInvalidTokenFormat,
			expectErrorMsg: "token contains an invalid number of segments",
			mock: func() {
				client.EXPECT().GetGrantTypes().Return(fosite.Arguments{jwtBearerGrantType})
				client.EXPECT().GetScopes().Return(fosite.Arguments{"foo-scope"})
				areq.EXPECT().GetClient().Return(client)

				areq.EXPECT().GetGrantTypes().Return(fosite.Arguments{jwtBearerGrantType})
				areq.EXPECT().GetRequestedScopes().Return(fosite.Arguments{"foo-scope"})

				areq.EXPECT().GetRequestForm().Return(url.Values{"assertion": []string{"i-am-not-jwt"}})
			},
		},
		{
			description:    "should fail because JWT JOSE header has no 'kid' field",
			expectErr:      fosite.ErrTokenSignatureMismatch,
			expectErrorMsg: "key-set ID should be present in 'kid'",
			mock: func() {
				client.EXPECT().GetGrantTypes().Return(fosite.Arguments{jwtBearerGrantType})
				client.EXPECT().GetScopes().Return(fosite.Arguments{"foo-scope"})
				areq.EXPECT().GetClient().Return(client)

				areq.EXPECT().GetGrantTypes().Return(fosite.Arguments{jwtBearerGrantType})
				areq.EXPECT().GetRequestedScopes().Return(fosite.Arguments{"foo-scope"})

				token := generateTestJWT(make(jwt.MapClaims), make(map[string]interface{}), generateTestJWKSet())
				areq.EXPECT().GetRequestForm().Return(url.Values{"assertion": []string{token}})
			},
		},
		{
			description:    "should fail because key set used to sign JWT was not found by Hydra's Key Manager",
			expectErr:      fosite.ErrTokenSignatureMismatch,
			expectErrorMsg: "no key found",
			mock: func() {
				client.EXPECT().GetGrantTypes().Return(fosite.Arguments{jwtBearerGrantType})
				client.EXPECT().GetScopes().Return(fosite.Arguments{"foo-scope"})
				areq.EXPECT().GetClient().Return(client)

				areq.EXPECT().GetGrantTypes().Return(fosite.Arguments{jwtBearerGrantType})
				areq.EXPECT().GetRequestedScopes().Return(fosite.Arguments{"foo-scope"})

				headers := map[string]interface{}{
					"kid": "123set",
				}
				token := generateTestJWT(make(jwt.MapClaims), headers, generateTestJWKSet())
				keyManager.EXPECT().GetKey("123set", "public").Return(nil, fmt.Errorf("no key found"))
				areq.EXPECT().GetRequestForm().Return(url.Values{"assertion": []string{token}})
			},
		},
		{
			description:    "should fail because Hydra's Key Manager wrong key type",
			expectErr:      fosite.ErrTokenSignatureMismatch,
			expectErrorMsg: "convert to RSA Public",
			mock: func() {
				client.EXPECT().GetGrantTypes().Return(fosite.Arguments{jwtBearerGrantType})
				client.EXPECT().GetScopes().Return(fosite.Arguments{"foo-scope"})
				areq.EXPECT().GetClient().Return(client)

				areq.EXPECT().GetGrantTypes().Return(fosite.Arguments{jwtBearerGrantType})
				areq.EXPECT().GetRequestedScopes().Return(fosite.Arguments{"foo-scope"})

				jwkSet := generateTestJWKSet()
				headers := map[string]interface{}{
					"kid": "123set",
				}
				token := generateTestJWT(make(jwt.MapClaims), headers, jwkSet)
				keySetWithOnlyPrivateKey := &jose.JSONWebKeySet{Keys: []jose.JSONWebKey{jwkSet.Keys[0]}}
				keyManager.EXPECT().GetKey("123set", "public").Return(keySetWithOnlyPrivateKey, nil)
				areq.EXPECT().GetRequestForm().Return(url.Values{"assertion": []string{token}})
			},
		},
		{
			description: "should fail because JWT was signed with the key of another client",
			expectErr:   fosite.ErrTokenSignatureMismatch,
			mock: func() {
				client.EXPECT().GetGrantTypes().Return(fosite.Arguments{jwtBearerGrantType})
				client.EXPECT().GetScopes().Return(fosite.Arguments{"foo-scope"})
				areq.EXPECT().GetClient().Return(client)

				areq.EXPECT().GetGrantTypes().Return(fosite.Arguments{jwtBearerGrantType})
				areq.EXPECT().GetRequestedScopes().Return(fosite.Arguments{"foo-scope"})

				anotherClientJwkSet := generateTestJWKSet()
				myJwkSet := generateTestJWKSet()
				headers := map[string]interface{}{
					"kid": "123set",
				}
				token := generateTestJWT(make(jwt.MapClaims), headers, anotherClientJwkSet)
				keySetWithOnlyPublicKey := &jose.JSONWebKeySet{Keys: []jose.JSONWebKey{myJwkSet.Keys[1]}}
				keyManager.EXPECT().GetKey("123set", "public").Return(keySetWithOnlyPublicKey, nil)
				areq.EXPECT().GetRequestForm().Return(url.Values{"assertion": []string{token}})
			},
		},
		{
			description:    "should fail because 'iss' in JWT has wrong client ID",
			expectErr:      fosite.ErrTokenClaim,
			expectErrorMsg: "should be your client ID",
			mock: func() {
				client.EXPECT().GetGrantTypes().Return(fosite.Arguments{jwtBearerGrantType})
				client.EXPECT().GetScopes().Return(fosite.Arguments{"foo-scope"})
				client.EXPECT().GetID().Return("client_1")

				areq.EXPECT().GetClient().Return(client)
				areq.EXPECT().GetGrantTypes().Return(fosite.Arguments{jwtBearerGrantType})
				areq.EXPECT().GetRequestedScopes().Return(fosite.Arguments{"foo-scope"})

				jwkSet := generateTestJWKSet()
				headers := map[string]interface{}{
					"kid": "123set",
				}
				claims := jwt.MapClaims{
					"iss": "client_2",
				}
				token := generateTestJWT(claims, headers, jwkSet)
				keySetWithOnlyPublicKey := &jose.JSONWebKeySet{Keys: []jose.JSONWebKey{jwkSet.Keys[1]}}
				keyManager.EXPECT().GetKey("123set", "public").Return(keySetWithOnlyPublicKey, nil)
				areq.EXPECT().GetRequestForm().Return(url.Values{"assertion": []string{token}})
			},
		},
		{
			description:    "should fail because 'sub' is missing in JWT",
			expectErr:      fosite.ErrTokenClaim,
			expectErrorMsg: "Subject (sub) claim should be a nonempty string",
			mock: func() {
				client.EXPECT().GetGrantTypes().Return(fosite.Arguments{jwtBearerGrantType})
				client.EXPECT().GetScopes().Return(fosite.Arguments{"foo-scope"})
				client.EXPECT().GetID().Return("client_1")

				areq.EXPECT().GetClient().Return(client)
				areq.EXPECT().GetGrantTypes().Return(fosite.Arguments{jwtBearerGrantType})
				areq.EXPECT().GetRequestedScopes().Return(fosite.Arguments{"foo-scope"})

				jwkSet := generateTestJWKSet()
				headers := map[string]interface{}{
					"kid": "123set",
				}
				claims := jwt.MapClaims{
					"iss": "client_1",
				}
				token := generateTestJWT(claims, headers, jwkSet)
				keySetWithOnlyPublicKey := &jose.JSONWebKeySet{Keys: []jose.JSONWebKey{jwkSet.Keys[1]}}
				keyManager.EXPECT().GetKey("123set", "public").Return(keySetWithOnlyPublicKey, nil)
				areq.EXPECT().GetRequestForm().Return(url.Values{"assertion": []string{token}})
			},
		},
		{
			description:    "should fail because 'sub' is an empty string",
			expectErr:      fosite.ErrTokenClaim,
			expectErrorMsg: "Subject (sub) claim should be a nonempty string",
			mock: func() {
				client.EXPECT().GetGrantTypes().Return(fosite.Arguments{jwtBearerGrantType})
				client.EXPECT().GetScopes().Return(fosite.Arguments{"foo-scope"})
				client.EXPECT().GetID().Return("client_1")

				areq.EXPECT().GetClient().Return(client)
				areq.EXPECT().GetGrantTypes().Return(fosite.Arguments{jwtBearerGrantType})
				areq.EXPECT().GetRequestedScopes().Return(fosite.Arguments{"foo-scope"})

				jwkSet := generateTestJWKSet()
				headers := map[string]interface{}{
					"kid": "123set",
				}
				claims := jwt.MapClaims{
					"iss": "client_1",
					"sub": "",
				}
				token := generateTestJWT(claims, headers, jwkSet)
				keySetWithOnlyPublicKey := &jose.JSONWebKeySet{Keys: []jose.JSONWebKey{jwkSet.Keys[1]}}
				keyManager.EXPECT().GetKey("123set", "public").Return(keySetWithOnlyPublicKey, nil)
				areq.EXPECT().GetRequestForm().Return(url.Values{"assertion": []string{token}})
			},
		},
		{
			description:    "should fail because 'sub' is not a string",
			expectErr:      fosite.ErrTokenClaim,
			expectErrorMsg: "Subject (sub) claim should be a nonempty string",
			mock: func() {
				client.EXPECT().GetGrantTypes().Return(fosite.Arguments{jwtBearerGrantType})
				client.EXPECT().GetScopes().Return(fosite.Arguments{"foo-scope"})
				client.EXPECT().GetID().Return("client_1")

				areq.EXPECT().GetClient().Return(client)
				areq.EXPECT().GetGrantTypes().Return(fosite.Arguments{jwtBearerGrantType})
				areq.EXPECT().GetRequestedScopes().Return(fosite.Arguments{"foo-scope"})

				jwkSet := generateTestJWKSet()
				headers := map[string]interface{}{
					"kid": "123set",
				}
				claims := jwt.MapClaims{
					"iss": "client_1",
					"sub": 123456,
				}
				token := generateTestJWT(claims, headers, jwkSet)
				keySetWithOnlyPublicKey := &jose.JSONWebKeySet{Keys: []jose.JSONWebKey{jwkSet.Keys[1]}}
				keyManager.EXPECT().GetKey("123set", "public").Return(keySetWithOnlyPublicKey, nil)
				areq.EXPECT().GetRequestForm().Return(url.Values{"assertion": []string{token}})
			},
		},
		{
			description:    "should fail because 'aud' in JWT has unknown OAuth2 token endpoint URL",
			expectErr:      fosite.ErrTokenClaim,
			expectErrorMsg: "Audience (aud) is invalid or missing",
			mock: func() {
				client.EXPECT().GetGrantTypes().Return(fosite.Arguments{jwtBearerGrantType})
				client.EXPECT().GetScopes().Return(fosite.Arguments{"foo-scope"})
				client.EXPECT().GetID().Return("client_1")

				areq.EXPECT().GetClient().Return(client)
				areq.EXPECT().GetGrantTypes().Return(fosite.Arguments{jwtBearerGrantType})
				areq.EXPECT().GetRequestedScopes().Return(fosite.Arguments{"foo-scope"})

				jwkSet := generateTestJWKSet()
				headers := map[string]interface{}{
					"kid": "123set",
				}
				claims := jwt.MapClaims{
					"iss": "client_1",
					"sub": "some-user-id",
					"aud": "http://some-other-oauth2-cluster.url",
				}
				token := generateTestJWT(claims, headers, jwkSet)
				keySetWithOnlyPublicKey := &jose.JSONWebKeySet{Keys: []jose.JSONWebKey{jwkSet.Keys[1]}}
				keyManager.EXPECT().GetKey("123set", "public").Return(keySetWithOnlyPublicKey, nil)
				areq.EXPECT().GetRequestForm().Return(url.Values{"assertion": []string{token}})
			},
		},
		{
			description: "should fail because 'exp' token time is expired",
			expectErr:   fosite.ErrTokenExpired,
			mock: func() {
				client.EXPECT().GetGrantTypes().Return(fosite.Arguments{jwtBearerGrantType})
				client.EXPECT().GetScopes().Return(fosite.Arguments{"foo-scope"})

				areq.EXPECT().GetClient().Return(client)
				areq.EXPECT().GetGrantTypes().Return(fosite.Arguments{jwtBearerGrantType})
				areq.EXPECT().GetRequestedScopes().Return(fosite.Arguments{"foo-scope"})

				jwkSet := generateTestJWKSet()
				headers := map[string]interface{}{
					"kid": "123set",
				}
				claims := jwt.MapClaims{
					"iss": "client_1",
					"sub": "some-user-id",
					"aud": "http://hydra-cluster.url/oauth2/token",
					"exp": time.Now().Add(time.Hour * -24).Unix(),
				}
				token := generateTestJWT(claims, headers, jwkSet)
				keySetWithOnlyPublicKey := &jose.JSONWebKeySet{Keys: []jose.JSONWebKey{jwkSet.Keys[1]}}
				keyManager.EXPECT().GetKey("123set", "public").Return(keySetWithOnlyPublicKey, nil)
				areq.EXPECT().GetRequestForm().Return(url.Values{"assertion": []string{token}})
			},
		},
		{
			description:    "should fail because 'exp' claim is not set in JWT",
			expectErr:      fosite.ErrTokenClaim,
			expectErrorMsg: "Expires (exp) claim should be present",
			mock: func() {
				client.EXPECT().GetGrantTypes().Return(fosite.Arguments{jwtBearerGrantType})
				client.EXPECT().GetScopes().Return(fosite.Arguments{"foo-scope"})
				client.EXPECT().GetID().Return("client_1")

				areq.EXPECT().GetClient().Return(client)
				areq.EXPECT().GetGrantTypes().Return(fosite.Arguments{jwtBearerGrantType})
				areq.EXPECT().GetRequestedScopes().Return(fosite.Arguments{"foo-scope"})

				jwkSet := generateTestJWKSet()
				headers := map[string]interface{}{
					"kid": "123set",
				}
				claims := jwt.MapClaims{
					"iss": "client_1",
					"sub": "some-user-id",
					"aud": "http://hydra-cluster.url/oauth2/token",
				}
				token := generateTestJWT(claims, headers, jwkSet)
				keySetWithOnlyPublicKey := &jose.JSONWebKeySet{Keys: []jose.JSONWebKey{jwkSet.Keys[1]}}
				keyManager.EXPECT().GetKey("123set", "public").Return(keySetWithOnlyPublicKey, nil)
				areq.EXPECT().GetRequestForm().Return(url.Values{"assertion": []string{token}})
			},
		},
		{
			description: "should fail because JWT is issued at some time in the future",
			expectErr:   fosite.ErrInactiveToken,
			mock: func() {
				client.EXPECT().GetGrantTypes().Return(fosite.Arguments{jwtBearerGrantType})
				client.EXPECT().GetScopes().Return(fosite.Arguments{"foo-scope"})

				areq.EXPECT().GetClient().Return(client)
				areq.EXPECT().GetGrantTypes().Return(fosite.Arguments{jwtBearerGrantType})
				areq.EXPECT().GetRequestedScopes().Return(fosite.Arguments{"foo-scope"})

				jwkSet := generateTestJWKSet()
				headers := map[string]interface{}{
					"kid": "123set",
				}
				claims := jwt.MapClaims{
					"iat": time.Now().Add(time.Hour * 200).Unix(),
				}
				token := generateTestJWT(claims, headers, jwkSet)
				keySetWithOnlyPublicKey := &jose.JSONWebKeySet{Keys: []jose.JSONWebKey{jwkSet.Keys[1]}}
				keyManager.EXPECT().GetKey("123set", "public").Return(keySetWithOnlyPublicKey, nil)
				areq.EXPECT().GetRequestForm().Return(url.Values{"assertion": []string{token}})
			},
		},
		{
			description:    "should fail because 'iat' claim is not set in JWT",
			expectErr:      fosite.ErrTokenClaim,
			expectErrorMsg: "Issued at (iat) claim should be present",
			mock: func() {
				client.EXPECT().GetGrantTypes().Return(fosite.Arguments{jwtBearerGrantType})
				client.EXPECT().GetScopes().Return(fosite.Arguments{"foo-scope"})
				client.EXPECT().GetID().Return("client_1")

				areq.EXPECT().GetClient().Return(client)
				areq.EXPECT().GetGrantTypes().Return(fosite.Arguments{jwtBearerGrantType})
				areq.EXPECT().GetRequestedScopes().Return(fosite.Arguments{"foo-scope"})

				jwkSet := generateTestJWKSet()
				headers := map[string]interface{}{
					"kid": "123set",
				}
				claims := jwt.MapClaims{
					"iss": "client_1",
					"sub": "some-user-id",
					"aud": "http://hydra-cluster.url/oauth2/token",
					"exp": time.Now().Add(time.Hour).Unix(),
				}
				token := generateTestJWT(claims, headers, jwkSet)
				keySetWithOnlyPublicKey := &jose.JSONWebKeySet{Keys: []jose.JSONWebKey{jwkSet.Keys[1]}}
				keyManager.EXPECT().GetKey("123set", "public").Return(keySetWithOnlyPublicKey, nil)
				areq.EXPECT().GetRequestForm().Return(url.Values{"assertion": []string{token}})
			},
		},
		{
			description:    "should fail because public clients are not allowed to use this grant-type",
			expectErr:      fosite.ErrInvalidGrant,
			expectErrorMsg: "not allowed to use grant type",
			mock: func() {
				client.EXPECT().GetGrantTypes().Return(fosite.Arguments{jwtBearerGrantType})
				client.EXPECT().GetScopes().Return(fosite.Arguments{"foo-scope"})
				client.EXPECT().GetID().Return("client_1")
				client.EXPECT().IsPublic().Return(true)

				areq.EXPECT().GetClient().Return(client)
				areq.EXPECT().GetGrantTypes().Return(fosite.Arguments{jwtBearerGrantType})
				areq.EXPECT().GetRequestedScopes().Return(fosite.Arguments{"foo-scope"})

				jwkSet := generateTestJWKSet()
				headers := map[string]interface{}{
					"kid": "123set",
				}
				claims := jwt.MapClaims{
					"iss": "client_1",
					"sub": "some-user-id",
					"aud": "http://hydra-cluster.url/oauth2/token",
					"iat": time.Now().Add(time.Hour * -1).Unix(),
					"exp": time.Now().Add(time.Hour).Unix(),
				}
				token := generateTestJWT(claims, headers, jwkSet)
				keySetWithOnlyPublicKey := &jose.JSONWebKeySet{Keys: []jose.JSONWebKey{jwkSet.Keys[1]}}
				keyManager.EXPECT().GetKey("123set", "public").Return(keySetWithOnlyPublicKey, nil)
				areq.EXPECT().GetRequestForm().Return(url.Values{"assertion": []string{token}})
			},
		},
		{
			description: "should fail because the request session is not of an appropriate type",
			expectErr:   openid.ErrInvalidSession,
			mock: func() {
				client.EXPECT().GetGrantTypes().Return(fosite.Arguments{jwtBearerGrantType})
				client.EXPECT().GetScopes().Return(fosite.Arguments{"foo-scope"})
				client.EXPECT().GetID().Return("client_1")
				client.EXPECT().IsPublic().Return(false)

				areq.EXPECT().GetClient().Return(client)
				areq.EXPECT().GetGrantTypes().Return(fosite.Arguments{jwtBearerGrantType})
				areq.EXPECT().GetRequestedScopes().Return(fosite.Arguments{"foo-scope"})

				areq.EXPECT().GetSession().Return(nil)

				jwkSet := generateTestJWKSet()
				headers := map[string]interface{}{
					"kid": "123set",
				}
				claims := jwt.MapClaims{
					"iss": "client_1",
					"sub": "some-user-id",
					"aud": "http://hydra-cluster.url/oauth2/token",
					"iat": time.Now().Add(time.Hour * -1).Unix(),
					"exp": time.Now().Add(time.Hour).Unix(),
				}
				token := generateTestJWT(claims, headers, jwkSet)
				keySetWithOnlyPublicKey := &jose.JSONWebKeySet{Keys: []jose.JSONWebKey{jwkSet.Keys[1]}}
				keyManager.EXPECT().GetKey("123set", "public").Return(keySetWithOnlyPublicKey, nil)
				areq.EXPECT().GetRequestForm().Return(url.Values{"assertion": []string{token}})
			},
		},
	} {
		t.Logf("Running test case %d", k)
		c.mock()
		err := h.HandleTokenEndpointRequest(nil, areq)
		assert.True(t, errors.Cause(err) == c.expectErr, "(%d) %s\nExpected: %s\nGot: %s", k, c.description, c.expectErr, err)
		assert.Contains(t, err.Error(), c.expectErrorMsg,
			"(%d) %s\nMessage expected to contain: %s\nGot: %s", k, c.description, c.expectErrorMsg, err.Error())
	}
}

func TestJWTBearerFlow_HandleTokenEndpointRequest_SessionPopulation(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	strategy := internal.NewMockAccessTokenStrategy(ctrl)
	store := internal.NewMockAccessTokenStorage(ctrl)
	keyManager := internal.NewMockManager(ctrl)
	areq := internal.NewMockAccessRequester(ctrl)
	client := internal.NewMockClient(ctrl)

	h := JWTBearerGrantHandler{
		HandleHelper: &oauth2.HandleHelper{
			AccessTokenStrategy: strategy,
			AccessTokenStorage:  store,
			AccessTokenLifespan: time.Hour,
		},
		ScopeStrategy: fosite.HierarchicScopeStrategy,
		KeyManager:    keyManager,
		Audience:      "http://hydra-cluster.url/oauth2/token",
	}

	client.EXPECT().GetGrantTypes().Return(fosite.Arguments{jwtBearerGrantType})
	client.EXPECT().GetScopes().Return(fosite.Arguments{"foo-scope"})
	client.EXPECT().GetID().Return("client_1")
	client.EXPECT().IsPublic().Return(false)

	areq.EXPECT().GetClient().Return(client)
	areq.EXPECT().GetGrantTypes().Return(fosite.Arguments{jwtBearerGrantType})
	areq.EXPECT().GetRequestedScopes().Return(fosite.Arguments{"foo-scope"})

	jwkSet := generateTestJWKSet()
	headers := map[string]interface{}{
		"kid": "123set",
	}
	claims := jwt.MapClaims{
		"iss": "client_1",
		"sub": "some-user-id",
		"aud": "http://hydra-cluster.url/oauth2/token",
		"iat": time.Now().Add(time.Hour * -1).Unix(),
		"exp": time.Now().Add(time.Hour).Unix(),
		"tnt": "some_tenant_1",
	}
	token := generateTestJWT(claims, headers, jwkSet)
	keySetWithOnlyPublicKey := &jose.JSONWebKeySet{Keys: []jose.JSONWebKey{jwkSet.Keys[1]}}
	keyManager.EXPECT().GetKey("123set", "public").Return(keySetWithOnlyPublicKey, nil)
	areq.EXPECT().GetRequestForm().Return(url.Values{"assertion": []string{token}})

	session := &Session{
		DefaultSession: &openid.DefaultSession{},
	}
	areq.EXPECT().GetSession().Return(session)

	err := h.HandleTokenEndpointRequest(nil, areq)
	assert.Nil(t, err, "Should finish without errors")
	assert.NotNil(t, session.ExpiresAt, "Should set expires to session")
	assert.Equal(t, "some-user-id", session.Subject, "Should set Subject based on 'sub' claim")
	assert.NotNil(t, session.Extra)
	assert.Contains(t, session.Extra, "tenant")
	assert.Equal(t, "some_tenant_1", session.Extra["tenant"], "Should set tenant to extra fields based on 'tnt' claim")
}

func TestJWTBearerFlow_PopulateTokenEndpointResponse(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	store := internal.NewMockAccessTokenStorage(ctrl)
	tokenStrategy := internal.NewMockAccessTokenStrategy(ctrl)
	areq := fosite.NewAccessRequest(new(fosite.DefaultSession))
	aresp := fosite.NewAccessResponse()

	h := JWTBearerGrantHandler{
		HandleHelper: &oauth2.HandleHelper{
			AccessTokenStorage:  store,
			AccessTokenStrategy: tokenStrategy,
			AccessTokenLifespan: time.Hour,
		},
		ScopeStrategy: fosite.HierarchicScopeStrategy,
		KeyManager:    nil,
		Audience:      "http://hydra-cluster.url/oauth2/token",
	}

	for k, c := range []struct {
		description string
		mock        func()
		req         *http.Request
		expectErr   error
	}{
		{
			description: "should fail because not responsible",
			expectErr:   fosite.ErrUnknownRequest,
			mock: func() {
				areq.GrantTypes = fosite.Arguments{""}
			},
		},
		{
			description: "should fail because client not allowed",
			expectErr:   fosite.ErrInvalidGrant,
			mock: func() {
				areq.GrantTypes = fosite.Arguments{jwtBearerGrantType}
				areq.Client = &fosite.DefaultClient{GrantTypes: fosite.Arguments{"foo"}}
			},
		},
		{
			description: "should pass",
			mock: func() {
				areq.GrantTypes = fosite.Arguments{jwtBearerGrantType}
				areq.Session = &fosite.DefaultSession{}
				areq.Client = &fosite.DefaultClient{GrantTypes: fosite.Arguments{jwtBearerGrantType}}
				tokenStrategy.EXPECT().GenerateAccessToken(nil, areq).Return("tokenfoo.bar", "bar", nil)
				store.EXPECT().CreateAccessTokenSession(nil, "bar", areq).Return(nil)
			},
		},
	} {
		t.Logf("Running test case %d", k)
		c.mock()
		err := h.PopulateTokenEndpointResponse(nil, areq, aresp)
		assert.True(t, errors.Cause(err) == c.expectErr, "(%d) %s\nExpected: %s\nGot: %s", k, c.description, c.expectErr, err)
	}
}

// generateTestJWT creates a valid test RSA-256 signed JWT with provided claims.
func generateTestJWT(claims jwt.MapClaims, headers map[string]interface{}, keySet *jose.JSONWebKeySet) string {
	token := jwt.New(jwt.SigningMethodRS256)
	token.Claims = claims
	for k, v := range headers {
		token.Header[k] = v
	}

	rsaKey, _ := jwk.First(keySet.Keys).Key.(*rsa.PrivateKey)
	encoded, _ := token.SigningString()
	signature, _ := token.Method.Sign(encoded, rsaKey)

	return fmt.Sprintf("%s.%s", encoded, signature)
}

// generateTestJWKSet creates a RSA-256 JWK for test purposes.
func generateTestJWKSet() *jose.JSONWebKeySet {
	var keyGenerator = &jwk.RS256Generator{}
	pk, _ := keyGenerator.Generate("")
	return pk
}
