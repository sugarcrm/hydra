package oauth2_test

import (
	"testing"

	"github.com/ory/hydra/oauth2"
	"github.com/stretchr/testify/assert"
)

func TestSetExtra(t *testing.T) {
	session := oauth2.NewSession("foo")
	assert.Nil(t, session.Extra)

	session.SetExtra("one", 1)
	assert.NotNil(t, session.Extra)
	assert.Contains(t, session.Extra, "one")
	assert.Equal(t, 1, session.Extra["one"])

	session.SetExtra("two", 2)
	assert.NotNil(t, session.Extra)
	assert.Contains(t, session.Extra, "one")
	assert.Equal(t, 1, session.Extra["one"])
	assert.Contains(t, session.Extra, "two")
	assert.Equal(t, 2, session.Extra["two"])
}
