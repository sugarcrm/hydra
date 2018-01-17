package oauth2

import (
	"time"

	"github.com/gorilla/sessions"
	"github.com/ory/fosite"
	"net/url"
	"github.com/pkg/errors"
	"github.com/pborman/uuid"
)

type ExtraParametersConsentStrategy struct {
	Issuer string

	DefaultIDTokenLifespan   time.Duration
	DefaultChallengeLifespan time.Duration
	ConsentManager           ConsentRequestManager
	ExtraParameters []string
}

func (s *ExtraParametersConsentStrategy) ValidateConsentRequest(req fosite.AuthorizeRequester, session string, cookie *sessions.Session) (claims *Session, err error) {
	defaultStrategy := &DefaultConsentStrategy{
		Issuer:                   s.Issuer,
		ConsentManager:           s.ConsentManager,
		DefaultChallengeLifespan: s.DefaultChallengeLifespan,
		DefaultIDTokenLifespan:   s.DefaultIDTokenLifespan,
	}

	return defaultStrategy.ValidateConsentRequest(req, session, cookie)
}

func (s *ExtraParametersConsentStrategy) CreateConsentRequest(req fosite.AuthorizeRequester, redirectURL string, cookie *sessions.Session) (string, error) {
	csrf := uuid.New()
	id := uuid.New()

	cookie.Values[CookieCSRFKey] = csrf
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

	consent := &ConsentRequest{
		ID:               id,
		CSRF:             csrf,
		GrantedScopes:    []string{},
		RequestedScopes:  req.GetRequestedScopes(),
		ClientID:         req.GetClient().GetID(),
		ExpiresAt:        time.Now().Add(s.DefaultChallengeLifespan),
		RedirectURL:      redirectURL + "&consent=" + id,
		AccessTokenExtra: atExt,
		IDTokenExtra:     map[string]interface{}{},
	}

	if err := s.ConsentManager.PersistConsentRequest(consent); err != nil {
		return "", errors.WithStack(err)
	}

	return id, nil
}
