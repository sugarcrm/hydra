package oauth2

import (
	"github.com/ory/hydra/jwk"
	"github.com/ory/hydra/pkg"
)

// CommonStore is Hydra specific store that obtains additional information for the application.
type CommonStore struct {
	jwk.Manager
	pkg.FositeStorer
	ClusterURL string
}
