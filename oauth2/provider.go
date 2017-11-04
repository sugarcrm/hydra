package oauth2

import (
	"context"
	"net/http"
	"net/url"
	"strings"

	"github.com/dgrijalva/jwt-go"
	"github.com/ory/fosite"
	"github.com/pkg/errors"
)

// HydraOAuth2Provider is a provider specific for Hydra needs an extension of Fosite OAuth2 provider.
type HydraOAuth2Provider struct {
	*fosite.Fosite
}

// NewAccessRequest creates a new access request.
func (f *HydraOAuth2Provider) NewAccessRequest(ctx context.Context, r *http.Request, session fosite.Session) (fosite.AccessRequester, error) {
	var err error
	accessRequest := fosite.NewAccessRequest(session)

	if r.Method != "POST" {
		return accessRequest, errors.Wrap(fosite.ErrInvalidRequest, "HTTP method is not POST")
	} else if err := r.ParseForm(); err != nil {
		return accessRequest, errors.Wrap(fosite.ErrInvalidRequest, err.Error())
	}

	accessRequest.Form = r.PostForm
	if session == nil {
		return accessRequest, errors.New("Session must not be nil")
	}

	accessRequest.SetRequestedScopes(removeEmpty(strings.Split(r.PostForm.Get("scope"), " ")))
	accessRequest.GrantTypes = removeEmpty(strings.Split(r.PostForm.Get("grant_type"), " "))
	if len(accessRequest.GrantTypes) < 1 {
		return accessRequest, errors.Wrap(fosite.ErrInvalidRequest, "No grant type given")
	}

	isJWTBearerFlow := fosite.StringInSlice(jwtBearerGrantType, accessRequest.GrantTypes)

	// Decode client_id and client_secret which should be in "application/x-www-form-urlencoded" format.
	var clientID, clientSecret string

	if isJWTBearerFlow {
		token, _ := jwt.Parse(accessRequest.GetRequestForm().Get("assertion"),
			func(token *jwt.Token) (interface{}, error) { return "", nil })
		if token == nil {
			return accessRequest, errors.Wrap(fosite.ErrInvalidRequest, "JWT failed to be parsed")
		}
		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			return nil, errors.Wrap(fosite.ErrInvalidTokenFormat, "JWT claims were not found or are malformed")
		}
		// Client ID should be denoted by 'iss' claim. It's not a part of RFC, but rather application-specific.
		clientID, _ = claims["iss"].(string)
		if clientID == "" {
			return accessRequest, errors.Wrap(fosite.ErrInvalidRequest, "Client id should be specified in 'iss' claim")
		}
	} else if id, secret, ok := r.BasicAuth(); !ok && !isJWTBearerFlow {
		return accessRequest, errors.Wrap(fosite.ErrInvalidRequest, "HTTP authorization header missing or invalid")
	} else if clientID, err = url.QueryUnescape(id); err != nil {
		return accessRequest, errors.Wrap(fosite.ErrInvalidRequest, `The client id in the HTTP authorization header could not be decoded from "application/x-www-form-urlencoded"`)
	} else if clientSecret, err = url.QueryUnescape(secret); err != nil {
		return accessRequest, errors.Wrap(fosite.ErrInvalidRequest, `The client secret in the HTTP authorization header could not be decoded from "application/x-www-form-urlencoded"`)
	}

	client, err := f.Store.GetClient(ctx, clientID)
	if err != nil {
		return accessRequest, errors.Wrap(fosite.ErrInvalidClient, err.Error())
	}

	if !client.IsPublic() && !isJWTBearerFlow {
		// Enforce client authentication
		if err := f.Hasher.Compare(client.GetHashedSecret(), []byte(clientSecret)); err != nil {
			return accessRequest, errors.Wrap(fosite.ErrInvalidClient, err.Error())
		}
	}

	accessRequest.Client = client

	found := false
	for _, loader := range f.TokenEndpointHandlers {
		if err := loader.HandleTokenEndpointRequest(ctx, accessRequest); err == nil {
			found = true
		} else if errors.Cause(err) == fosite.ErrUnknownRequest {
			// do nothing
		} else if err != nil {
			return accessRequest, err
		}
	}

	if !found {
		return nil, errors.WithStack(fosite.ErrInvalidRequest)
	}
	return accessRequest, nil
}

// removeEmpty removes empty strings from array.
func removeEmpty(args []string) (ret []string) {
	for _, v := range args {
		v = strings.TrimSpace(v)
		if v != "" {
			ret = append(ret, v)
		}
	}
	return
}
