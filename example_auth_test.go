package auth_test

import (
	"context"
	"encoding/json"
	"fmt"

	auth "github.com/pilacorp/nda-auth-sdk"
	"github.com/pilacorp/nda-auth-sdk/provider"
)

// ExampleNewAuth demonstrates how to create a new Auth instance.
func ExampleNewAuth() {
	// Create a Vault provider for signing operations
	provider := provider.NewVaultProvider("https://vault-dev.pila.vn", "", 3)

	// Create an Auth instance with the provider and DID URL
	authInstance := auth.NewAuth(provider, "https://auth-dev.pila.vn/api/v1/did")

	fmt.Printf("Auth instance created: %v\n", authInstance != nil)
	// Output: Auth instance created: true
}

// ExampleAuth_CreateToken demonstrates how to create a VP token from Verifiable Credentials.
func ExampleAuth_CreateToken() {
	// Initialize Auth with provider
	provider := provider.NewVaultProvider("https://vault-dev.pila.vn", "", 3)
	authInstance := auth.NewAuth(provider, "https://auth-dev.pila.vn/api/v1/did")

	// Prepare VC JWT tokens (these are example tokens - replace with real ones)
	vcJwts := []string{
		"eyJhbGciOiJFUzI1NksiLCJraWQiOiJkaWQ6bmRhOnRlc3RuZXQ6MHgxNmM1MTMwZGVmNjQ5NmY1ZGU5M2Y5MDc2YTVjZWIwNWNlNTllNGIwI2tleS0xIiwidHlwIjoiSldUIn0...",
		// Add more VC JWT tokens as needed
	}

	// Holder DID - the entity that owns and presents these credentials
	holderDid := "did:nda:testnet:0x2af7e8ebfec14f5e39469d2ce8442a5eef9f3fa4"

	// Create a VP token containing the VCs
	token, err := authInstance.CreateToken(context.Background(), vcJwts, holderDid)
	if err != nil {
		fmt.Printf("Error creating token: %v\n", err)
		return
	}

	fmt.Printf("Token created successfully (length: %d)\n", len(token))
	// Output: Token created successfully (length: <some number>)
}

// ExampleAuth_VerifyToken demonstrates how to verify a VP token and extract VC claims.
func ExampleAuth_VerifyToken() {
	// Initialize Auth with provider
	provider := provider.NewVaultProvider("https://vault-dev.pila.vn", "", 3)
	authInstance := auth.NewAuth(provider, "https://auth-dev.pila.vn/api/v1/did")

	// VP token to verify (this would typically come from a client request)
	token := "eyJhbGciOiJFUzI1NksiLCJraWQiOiJkaWQ6bmRhOnRlc3RuZXQ6MHgyYWY3ZThlYmZlYzE0ZjVlMzk0NjlkMmNlODQ0MmE1ZWVmOWYzZmE0I2tleS0xIiwidHlwIjoiSldUIn0..."

	// Verify the token and extract VC claims
	claims, err := authInstance.VerifyToken(context.Background(), token)
	if err != nil {
		fmt.Printf("Error verifying token: %v\n", err)
		return
	}

	// Process the claims
	for i, claim := range claims {
		claimJSON, _ := json.MarshalIndent(claim, "", "  ")
		fmt.Printf("VC Claim %d:\n%s\n", i+1, string(claimJSON))
	}

	fmt.Printf("Token verified successfully, found %d credential(s)\n", len(claims))
	// Output: Token verified successfully, found <number> credential(s)
}

// ExampleAuth_workflow demonstrates a complete workflow: creating and verifying a token.
func ExampleAuth_workflow() {
	// Step 1: Initialize Auth
	provider := provider.NewVaultProvider("https://vault-dev.pila.vn", "", 3)
	authInstance := auth.NewAuth(provider, "https://auth-dev.pila.vn/api/v1/did")

	// Step 2: Create a token from VCs
	vcJwts := []string{
		"eyJhbGciOiJFUzI1NksiLCJraWQiOiJkaWQ6bmRhOnRlc3RuZXQ6MHgxNmM1MTMwZGVmNjQ5NmY1ZGU5M2Y5MDc2YTVjZWIwNWNlNTllNGIwI2tleS0xIiwidHlwIjoiSldUIn0...",
	}
	holderDid := "did:nda:testnet:0x2af7e8ebfec14f5e39469d2ce8442a5eef9f3fa4"

	token, err := authInstance.CreateToken(context.Background(), vcJwts, holderDid)
	if err != nil {
		fmt.Printf("Failed to create token: %v\n", err)
		return
	}

	// Step 3: Verify the token
	claims, err := authInstance.VerifyToken(context.Background(), token)
	if err != nil {
		fmt.Printf("Failed to verify token: %v\n", err)
		return
	}

	fmt.Printf("Workflow completed: created and verified token with %d credential(s)\n", len(claims))
	// Output: Workflow completed: created and verified token with <number> credential(s)
}
