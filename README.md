# Go VC Auth SDK

A Go SDK for working with **Verifiable Credentials (VCs)** and **Verifiable Presentations (VPs)**. This library provides a simple interface for creating and verifying VP tokens that contain one or more VCs, with support for cryptographic signing via HashiCorp Vault.

## Features

- **Create VP Tokens**: Build Verifiable Presentations from multiple Verifiable Credentials
- **Verify VP Tokens**: Validate VP tokens and extract credential claims
- **Vault Integration**: Secure key management and signing via HashiCorp Vault
- **Provider Abstraction**: Extensible provider interface for custom signing implementations
- **DID Support**: Full support for Decentralized Identifiers (DIDs)

## Installation

```bash
go get github/hovanhoa/go-vc-auth
```

## Quick Start

### Basic Usage

```go
package main

import (
    "context"
    auth "github/hovanhoa/go-vc-auth"
)

func main() {
    // Initialize Auth with Vault provider
    authInstance := auth.NewAuthWithDefaultProvider(
        "http://vault:8200",              // Vault address
        "your-vault-token",               // Vault token
        "https://auth-dev.pila.vn/api/v1/did", // DID resolver URL
        3,                                // Max retries
    )

    // Create a VP token from VCs
    vcJwts := []string{
        "eyJhbGciOiJFUzI1NksiLCJraWQiOiJkaWQ6bmRhOnRlc3RuZXQ6MHgxNmM1MTMwZGVmNjQ5NmY1ZGU5M2Y5MDc2YTVjZWIwNWNlNTllNGIwI2tleS0xIiwidHlwIjoiSldUIn0...",
    }
    holderDid := "did:nda:testnet:0x2af7e8ebfec14f5e39469d2ce8442a5eef9f3fa4"
    
    token, err := authInstance.CreateToken(context.Background(), vcJwts, holderDid)
    if err != nil {
        panic(err)
    }

    // Verify the token
    claims, err := authInstance.VerifyToken(context.Background(), token)
    if err != nil {
        panic(err)
    }
    
    // Process claims...
}
```

## Architecture

### Core Components

- **`auth.go`**: Main `Auth` interface and implementation for creating and verifying VP tokens
- **`model.go`**: Data models for credentials and presentations
- **`provider.go`**: `Provider` interface for signing operations with default Vault implementation
- **`vault/`**: HashiCorp Vault integration for secure key storage and signing

### Key Interfaces

#### Auth Interface

```go
type Auth interface {
    // CreateToken creates a new VP token with a list of VCs
    CreateToken(ctx context.Context, vcsJwt []string, holderDid string) (string, error)

    // VerifyToken verifies a VP token and extracts VC claims
    VerifyToken(ctx context.Context, token string) ([]VcClaims, error)
}
```

#### Provider Interface

```go
type Provider interface {
    // Sign signs a payload using the configured private key
    Sign(payload []byte, options *ProviderOption) ([]byte, error)
}
```

## API Reference

### Creating an Auth Instance

#### With Custom Provider

```go
provider := auth.NewVaultProvider("http://vault:8200", "vault-token", 3)
authInstance := auth.NewAuth(provider, "https://auth-dev.pila.vn/api/v1/did")
```

#### With Default Vault Provider

```go
authInstance := auth.NewAuthWithDefaultProvider(
    "http://vault:8200",
    "vault-token",
    "https://auth-dev.pila.vn/api/v1/did",
    3, // max retries
)
```

### Creating a VP Token

```go
token, err := authInstance.CreateToken(ctx, vcsJwt, holderDid)
```

- **`vcsJwt`**: Array of VC JWT tokens to include in the presentation
- **`holderDid`**: DID of the entity presenting the credentials
- **Returns**: JSON string containing the VP token

### Verifying a VP Token

```go
claims, err := authInstance.VerifyToken(ctx, token)
```

- **`token`**: VP token JSON string to verify
- **Returns**: Array of `VcClaims` containing issuer and subject information

### VcClaims Structure

```go
type VcClaims struct {
    Issuer  string                 `json:"issuer"`
    Subject map[string]interface{} `json:"CredentialSubject"`
}
```

## Vault Integration

The SDK includes built-in support for HashiCorp Vault's `ethsign` plugin for secure key management and signing.

### Vault Configuration

The Vault provider expects:
- **Endpoint**: `/v1/secp/accounts` for storing private keys
- **Endpoint**: `/v1/secp/accounts/{address}/signRaw` for signing messages
- **Authentication**: X-Vault-Token header

### Vault Methods

- **`StorePrivateKey`**: Stores a private key in Vault and returns the associated Ethereum address
- **`SignMessage`**: Signs a 32-byte hash using a key stored in Vault

## Examples

See `example_auth_test.go` for complete usage examples including:
- Creating an Auth instance
- Creating VP tokens
- Verifying VP tokens
- Complete workflow examples

## Dependencies

- `github.com/pilacorp/go-credential-sdk`: Core VC/VP credential handling
- HashiCorp Vault: For secure key management (via HTTP API)

## Requirements

- Go 1.24.4 or later
- HashiCorp Vault with `ethsign` plugin enabled
- Access to a DID resolver service

## License

[Add your license here]
