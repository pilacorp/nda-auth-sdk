// package provider provides a provider interface for signing operations
package ethereum

import (
	"context"

	"github.com/ethereum/go-ethereum/crypto/secp256k1"
	"github.com/pilacorp/nda-auth-sdk/provider"
)

// providerPriv is the provider implementation that uses a private key for signing.
type providerPriv struct {
	privateKey []byte
}

// NewProviderPriv creates a new providerPriv instance.
// It initializes the provider with the provided private key.
func NewEthereumProvider(privateKey []byte) provider.Provider {
	return &providerPriv{
		privateKey: privateKey,
	}
}

// Sign signs the payload using the private key
func (p *providerPriv) Sign(ctx context.Context, payload []byte, opts ...provider.SignOption) ([]byte, error) {
	options := &provider.SignOptions{}
	for _, opt := range opts {
		opt(options)
	}

	return secp256k1.Sign(payload, options.PrivateKey)
}
