# Go VC Auth SDK

A Go SDK for working with **Verifiable Credentials (VCs)** and **Verifiable Presentations (VPs)**. This library provides a simple interface for creating and verifying VP tokens that contain one or more VCs, with support for cryptographic signing via HashiCorp Vault.

**Now supports DID-CapChain v1.1**: A capability-based authorization system using W3C Verifiable Credentials for multi-hop delegation and service access control.

## Features

- **Create VP Tokens**: Build Verifiable Presentations from multiple Verifiable Credentials
- **Verify VP Tokens**: Validate VP tokens and extract credential claims
- **DID-CapChain Support**: Create and verify CapChainPresentations with capability-based authorization
- **Verification Phase**: Verify VP/VC cryptographic validity and parse capability context
- **Authorization Phase**: Check service capabilities and resource capability chains with attenuation validation
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
    address := "0x2af7e8ebfec14f5e39469d2ce8442a5eef9f3fa4" // Address for signing
    
    token, err := authInstance.CreateToken(context.Background(), vcJwts, holderDid, address)
    if err != nil {
        panic(err)
    }

    // Verify the token
    claims, err := authInstance.VerifyToken(context.Background(), token)
    if err != nil {
        panic(err)
    }
    
    // Process claims...
    
    // Or verify into custom structs
    type MyClaims struct {
        Issuer      string   `json:"issuer"`
        Capsule     string   `json:"capsule"`
        CID         string   `json:"cid"`
        ID          string   `json:"id"`
        Permissions []string `json:"permissions"`
        Role        string   `json:"role"`
    }
    
    targets := []any{
        &MyClaims{},
        &MyClaims{},
    }
    
    err = authInstance.VerifyTokenWithStructs(context.Background(), token, targets)
    if err != nil {
        panic(err)
    }
    
    // Access parsed claims
    firstClaim := targets[0].(*MyClaims)
    fmt.Println("Role:", firstClaim.Role)
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
    CreateToken(ctx context.Context, vcsJwt []string, holderDid string, opts ...provider.SignOption) (string, error)

    // VerifyToken verifies a VP token and extracts VC claims
    VerifyToken(ctx context.Context, token string) ([]map[string]any, string, []string, error)

    // VerifyTokenWithStructs verifies a VP token and parses claims into structs
    VerifyTokenWithStructs(ctx context.Context, token string, targets []any) error

    // CreateCapChainPresentation creates a CapChainPresentation (DID-CapChain VP) with capability chains metadata
    CreateCapChainPresentation(ctx context.Context, vcsJwt []string, holderDid string, audienceDid string, chains []CapChainRef, opts ...provider.SignOption) (string, error)

    // VerifyVPContext performs Verification Phase - validates VP/VC and returns VerifiedVPContext
    VerifyVPContext(ctx context.Context, token string) (*VerifiedVPContext, error)

    // CheckServiceCapability performs ServiceCapability authorization check
    CheckServiceCapability(ctx context.Context, vpCtx *VerifiedVPContext, serviceDID string, action string, trustedIssuers []string) (*AuthorizationResult, error)

    // CheckResourceCapabilityChain performs ResourceCapabilityChain authorization check with attenuation validation
    CheckResourceCapabilityChain(ctx context.Context, vpCtx *VerifiedVPContext, resourceURN string, action string) (*AuthorizationResult, error)
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
token, err := authInstance.CreateToken(ctx, vcsJwt, holderDid, opts...)
```

- **`vcsJwt`**: Array of VC JWT tokens to include in the presentation
- **`holderDid`**: DID of the entity presenting the credentials
- **`opts`**: Optional variadic arguments passed to the provider's Sign method (e.g., address for signing)
- **Returns**: JSON string containing the VP token

### Verifying a VP Token

```go
claims, err := authInstance.VerifyToken(ctx, token)
```

- **`token`**: VP token JSON string to verify
- **Returns**: Array of `VcClaims` containing issuer and subject information

### Verifying a VP Token with Structs

```go
// Define your custom struct with flattened fields
type Claims struct {
    Issuer      string   `json:"issuer"`
    Capsule     string   `json:"capsule"`
    CID         string   `json:"cid"`
    ID          string   `json:"id"`
    Permissions []string `json:"permissions"`
    Role        string   `json:"role"`
}

// Verify and parse into structs
targets := []any{
    &Claims{},
    &Claims{}, // One struct per VC in the token
}

err := authInstance.VerifyTokenWithStructs(ctx, token, targets)
```

- **`token`**: VP token JSON string to verify
- **`targets`**: Array of pointers to structs (one for each VC in the token)
- **Returns**: Error if verification or parsing fails

**Note**: The function automatically flattens the credential structure, merging `credentialSubject` fields to the top level. Your struct should match this flattened structure (with `issuer` and all `credentialSubject` fields at the same level).

### VcClaims Structure

```go
type VcClaims struct {
    Issuer            string                 `json:"issuer"`
    CredentialSubject map[string]interface{} `json:"credentialSubject"`
}
```

## DID-CapChain v1.1

The SDK implements DID-CapChain v1.1, a capability-based authorization system that enables:

- **Resource Capability Chains**: Delegate access rights on specific resources through multi-hop delegation
- **Service Capabilities**: Grant permissions to call specific services with defined actions
- **Attenuation**: Ensure delegated capabilities never exceed the parent's scope

### Creating a CapChainPresentation

```go
// Define capability chains
chains := []auth.CapChainRef{
    {
        Kind:   auth.CapKindResource,
        Anchor: "urn:example:resource:123",
        LeafID: "urn:vc:cap:VC2",
    },
    {
        Kind:   auth.CapKindService,
        Anchor: "did:svc:StorageX",
        LeafID: "urn:vc:cap:VC3",
    },
}

// Create CapChainPresentation
token, err := authInstance.CreateCapChainPresentation(
    ctx,
    vcJwts,
    holderDid,
    audienceDid, // Service DID receiving the request
    chains,
    provider.WithSignerAddress(address),
)
```

### Verification Phase

The Verification Phase validates VP/VC cryptographic signatures and extracts capability context:

```go
vpCtx, err := authInstance.VerifyVPContext(ctx, token)
if err != nil {
    // Handle verification error
}

// Access verified context
fmt.Printf("Holder: %s\n", vpCtx.HolderDID)
fmt.Printf("Audience: %s\n", vpCtx.AudienceDID)
fmt.Printf("VCs: %d\n", len(vpCtx.VCs))
fmt.Printf("Chains: %d\n", len(vpCtx.Chains))
```

### Authorization Phase

#### Service Capability Check

Check if the actor has permission to call a service:

```go
trustedIssuers := []string{"did:svc:StorageX"}
result, err := authInstance.CheckServiceCapability(
    ctx,
    vpCtx,
    "did:svc:StorageX",
    "file.read",
    trustedIssuers,
)

if result.Authorized {
    // Allow access
} else {
    // Deny access: result.Reason contains explanation
}
```

#### Resource Capability Chain Check

Check if the actor has a valid capability chain for accessing a resource:

```go
result, err := authInstance.CheckResourceCapabilityChain(
    ctx,
    vpCtx,
    "urn:storagex:file:FILE_ID",
    "read",
)

if result.Authorized {
    // Allow access - chain validated with attenuation rule
} else {
    // Deny access: result.Reason contains explanation
}
```

### Capability Types

The SDK supports three types of capability credentials:

1. **ResourceCapabilityCredential** (`CapKindResource`): Direct access rights on a resource
2. **DelegatedCapabilityCredential** (`CapKindDelegate`): Delegated rights from another capability
3. **ServiceCapabilityCredential** (`CapKindService`): Permission to call a service

### Capability Structure

```go
type Capability struct {
    Kind       CapabilityKind `json:"kind"`
    Resource   string         `json:"resource,omitempty"`
    Service    string         `json:"service,omitempty"`
    Actions    []string       `json:"actions,omitempty"`
    OnBehalfOf string         `json:"onBehalfOf,omitempty"`
    Parent     string         `json:"parent,omitempty"`
}
```

### Attenuation Rule

The attenuation rule ensures that delegated capabilities cannot exceed the parent's scope:

- Actions(child) ⊆ Actions(parent)
- Resource(child) = Resource(parent)
- Delegation flow: parent.Subject == child.Issuer

This rule is automatically enforced during `CheckResourceCapabilityChain` validation.

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
- Verifying VP tokens into custom structs
- Complete workflow examples

## Dependencies

- `github.com/pilacorp/go-credential-sdk`: Core VC/VP credential handling
- HashiCorp Vault: For secure key management (via HTTP API)

## Requirements

- Go 1.24.4 or later
- HashiCorp Vault with `ethsign` plugin enabled
- Access to a DID resolver service

