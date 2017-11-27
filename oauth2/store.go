package oauth2

import (
	"github.com/ory/hydra/jwk"
	"github.com/ory/hydra/pkg"
)

// CommonStore is Hydra specific store that obtains additional information for the application.
type CommonStore struct {
	pkg.FositeStorer
	KeyManager jwk.Manager
	ClusterURL string
}
