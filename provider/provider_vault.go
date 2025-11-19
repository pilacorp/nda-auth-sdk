package provider

import (
	"context"
	"fmt"

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
func (v *vaultProvider) Sign(payload []byte, opts ...any) ([]byte, error) {
	if len(opts) == 0 {
		return nil, fmt.Errorf("signer address is required")
	}

	signerAddress := opts[0]
	return v.vault.SignMessage(context.Background(), payload, signerAddress.(string))
}
