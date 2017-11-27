package oauth2

import (
	"github.com/mohae/deepcopy"
	"github.com/ory/fosite"
	"github.com/ory/fosite/handler/openid"
	"github.com/ory/fosite/token/jwt"
)

// SessionExtraInfo is for extra values we want to be stored in session
type SessionExtraInfo map[string]interface{}

type Session struct {
	*openid.DefaultSession `json:"idToken"`
	Extra                  SessionExtraInfo `json:"extra"`
}

func NewSession(subject string) *Session {
	return &Session{
		DefaultSession: &openid.DefaultSession{
			Claims:  new(jwt.IDTokenClaims),
			Headers: new(jwt.Headers),
			Subject: subject,
		},
	}
}

func (s *Session) Clone() fosite.Session {
	if s == nil {
		return nil
	}

	return deepcopy.Copy(s).(fosite.Session)
}

// SetExtra sets one extra attribute to session.
// Additionally lazy-allocated Extra field.
func (s *Session) SetExtra(key string, value interface{}) {
	// Deferred initialization.
	if s.Extra == nil {
		s.Extra = make(SessionExtraInfo)
	}
	s.Extra[key] = value
}
