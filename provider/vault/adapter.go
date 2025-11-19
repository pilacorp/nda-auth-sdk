package vault

import (
	"context"

	"github.com/pilacorp/nda-auth-sdk/provider"
	"github.com/pilacorp/nda-auth-sdk/vault"
)

// vaultProvider is the provider implementation that uses Vault for signing.
type vaultProvider struct {
	vault *vault.Vault
}

// NewVaultProvider creates a new vaultProvider instance.
// It connects to Vault using the provided address and token and optional max retries.
func NewVaultProvider(address, token string, maxRetries ...int) provider.Provider {
	return &vaultProvider{
		vault: vault.NewVault(address, token, maxRetries...),
	}
}

// Sign signs the payload using Vault.
func (v *vaultProvider) Sign(ctx context.Context, payload []byte, opts ...provider.SignOption) ([]byte, error) {
	options := &provider.SignOptions{}
	for _, opt := range opts {
		opt(options)
	}

	return v.vault.SignMessage(ctx, payload, options.SignerAddress)
}
