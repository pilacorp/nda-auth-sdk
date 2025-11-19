package provider

import (
	"context"
	"errors"

	"github.com/pilacorp/nda-auth-sdk/vault"
)

// vaultProvider is the provider implementation that uses Vault for signing.
type vaultProvider struct {
	vault *vault.Vault
}

// NewVaultProvider creates a new vaultProvider instance.
// It connects to Vault using the provided address and token and optional max retries.
func NewVaultProvider(address, token string, maxRetries ...int) Provider {
	return &vaultProvider{
		vault: vault.NewVault(address, token, maxRetries...),
	}
}

// Sign signs the payload using Vault.
func (v *vaultProvider) Sign(ctx context.Context, payload []byte, options *ProviderOption) ([]byte, error) {
	if options == nil {
		return nil, errors.New("provider option is required")
	}

	signerAddress := options.SignerAddress
	if signerAddress == "" {
		return nil, errors.New("signer address is required")
	}
	return v.vault.SignMessage(ctx, payload, signerAddress)
}
