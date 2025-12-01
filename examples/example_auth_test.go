package auth_test

import (
	"fmt"

	"github.com/pilacorp/nda-auth-sdk/auth"
	"github.com/pilacorp/nda-auth-sdk/provider/vault"
)

// ExampleNewAuth demonstrates how to create a new Auth instance.
func ExampleNewAuth() {
	// Create a Vault provider for signing operations
	vaultProvider := vault.NewVaultProvider("https://vault-dev.pila.vn", "", 3)

	// Create an Auth instance with the provider and DID URL
	authInstance := auth.NewAuth(vaultProvider, "https://auth-dev.pila.vn/api/v1/did")

	fmt.Printf("Auth instance created: %v\n", authInstance != nil)
	// Output: Auth instance created: true
}
