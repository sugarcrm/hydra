package oauth2

import (
	"crypto/rsa"
	"fmt"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/sessions"
	"github.com/ory/fosite"
	"github.com/ory/hydra/jwk"
	"github.com/pborman/uuid"
	"github.com/pkg/errors"
	"net/url"
)

type ExtraParametersConsentStrategy struct {
	Issuer string

	DefaultIDTokenLifespan   time.Duration
	DefaultChallengeLifespan time.Duration
	KeyManager               jwk.Manager
	ExtraParameters []string
}

func (s *ExtraParametersConsentStrategy) ValidateResponse(a fosite.AuthorizeRequester, token string, session *sessions.Session) (claims *Session, err error) {
	defaultStrategy := &DefaultConsentStrategy{
		Issuer:                   s.Issuer,
		KeyManager:               s.KeyManager,
		DefaultChallengeLifespan: s.DefaultChallengeLifespan,
		DefaultIDTokenLifespan:   s.DefaultIDTokenLifespan,
	}

	return defaultStrategy.ValidateResponse(a, token, session)
}

func (s *ExtraParametersConsentStrategy) IssueChallenge(authorizeRequest fosite.AuthorizeRequester, redirectURL string, session *sessions.Session) (string, error) {
	token := jwt.New(jwt.SigningMethodRS256)
	jti := uuid.New()
	redirectURLParams, err := url.ParseQuery(redirectURL)
	if err != nil {
		return "", errors.WithStack(err)
	}
	atExt := make(map[string]interface{})
	for _, parameter := range s.ExtraParameters {
		if redirectURLParams[parameter] != nil {
			atExt[parameter] = redirectURLParams[parameter][0]
		}
	}
	token.Claims = jwt.MapClaims{
		"jti":    jti,
		"scp":    authorizeRequest.GetRequestedScopes(),
		"aud":    authorizeRequest.GetClient().GetID(),
		"exp":    time.Now().Add(s.DefaultChallengeLifespan).Unix(),
		"redir":  redirectURL,
		"at_ext": atExt,
	}

	session.Values["consent_jti"] = jti
	ks, err := s.KeyManager.GetKey(ConsentChallengeKey, "private")
	if err != nil {
		return "", errors.WithStack(err)
	}

	rsaKey, ok := jwk.First(ks.Keys).Key.(*rsa.PrivateKey)
	if !ok {
		return "", errors.New("Could not convert to RSA Private Key")
	}

	var signature, encoded string
	if encoded, err = token.SigningString(); err != nil {
		return "", errors.WithStack(err)
	} else if signature, err = token.Method.Sign(encoded, rsaKey); err != nil {
		return "", errors.WithStack(err)
	}

	return fmt.Sprintf("%s.%s", encoded, signature), nil

}
