#!/bin/sh

PROJECT_ROOT=github.com/ory/hydra
MOCKS_DIR=internal/mocks

mockgen -package internal -destination $MOCKS_DIR/fosite_access_token_strategy.go github.com/ory/fosite/handler/oauth2 AccessTokenStrategy
mockgen -package internal -destination $MOCKS_DIR/fosite_access_token_storage.go github.com/ory/fosite/handler/oauth2 AccessTokenStorage
mockgen -package internal -destination $MOCKS_DIR/fosite_access_request.go github.com/ory/fosite AccessRequester
mockgen -package internal -destination $MOCKS_DIR/fosite_client.go github.com/ory/fosite Client
mockgen -package internal -destination $MOCKS_DIR/hydra_key_manager.go github.com/ory/hydra/jwk Manager

# See https://github.com/golang/mock/issues/30
find $MOCKS_DIR -type f -exec sed -i.bak "s,$PROJECT_ROOT/vendor/,,g" {} \;
rm -rf $MOCKS_DIR/*.bak

goimports -w $MOCKS_DIR/
