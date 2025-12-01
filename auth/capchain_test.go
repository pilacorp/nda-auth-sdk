package auth_test

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"testing"
	"time"

	"github.com/pilacorp/nda-auth-sdk/auth"
	"github.com/pilacorp/nda-auth-sdk/provider"
	"github.com/pilacorp/nda-auth-sdk/provider/ethereum"
)

// Test helper: create a simple capability VC JWT for testing
// This creates a minimal valid JWT structure with capability data
func createTestCapabilityVCJWT(t *testing.T, issuerDID string, subjectDID string, jti string, capability map[string]interface{}) string {
	// Create JWT header
	header := map[string]interface{}{
		"alg": "ES256K",
		"kid": issuerDID + "#key-1",
		"typ": "JWT",
	}

	// Create JWT payload
	now := time.Now().Unix()
	payload := map[string]interface{}{
		"iss": issuerDID,
		"sub": subjectDID,
		"jti": jti,
		"nbf": now,
		"exp": now + 3600, // 1 hour
		"vc": map[string]interface{}{
			"@context": []interface{}{
				"https://www.w3.org/ns/credentials/v2",
				"https://did-capchain.org/contexts/capability-v1",
			},
			"type": []interface{}{
				"VerifiableCredential",
				"CapabilityCredential",
			},
			"credentialSubject": map[string]interface{}{
				"id":  subjectDID,
				"cap": capability,
			},
		},
	}

	// Encode header and payload
	headerBytes, _ := json.Marshal(header)
	payloadBytes, _ := json.Marshal(payload)

	headerB64 := base64.RawURLEncoding.EncodeToString(headerBytes)
	payloadB64 := base64.RawURLEncoding.EncodeToString(payloadBytes)

	// Create unsigned JWT (for testing, we'll use a mock signature)
	signature := "mock_signature_for_testing"
	return headerB64 + "." + payloadB64 + "." + signature
}

// TestVerifyVPContext tests the VerifyVPContext function
func TestVerifyVPContext(t *testing.T) {
	// Use Ethereum provider for testing
	privateKeyHex := "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
	privateKey, err := hex.DecodeString(privateKeyHex)
	if err != nil {
		t.Fatalf("failed to decode private key: %v", err)
	}

	ethereumProvider := ethereum.NewEthereumProvider(privateKey)
	authInstance := auth.NewAuth(ethereumProvider, "https://auth-dev.pila.vn/api/v1/did")

	// Create test capability VCs
	issuerDID := "did:svc:StorageX"
	holderDID := "did:app:A"
	resourceURN := "urn:storagex:file:FILE_ID"

	vc1 := createTestCapabilityVCJWT(t, issuerDID, "did:user:L", "urn:vc:cap:VC0", map[string]interface{}{
		"kind":     "resource",
		"resource": resourceURN,
		"actions":  []string{"read", "write"},
	})

	vc2 := createTestCapabilityVCJWT(t, "did:user:L", "did:user:H", "urn:vc:cap:VC1", map[string]interface{}{
		"kind":     "delegate",
		"resource": resourceURN,
		"actions":  []string{"read"},
		"parent":   "urn:vc:cap:VC0",
	})

	vc3 := createTestCapabilityVCJWT(t, "did:user:H", holderDID, "urn:vc:cap:VC2", map[string]interface{}{
		"kind":       "delegate",
		"resource":   resourceURN,
		"actions":    []string{"read"},
		"parent":     "urn:vc:cap:VC1",
		"onBehalfOf": "did:user:H",
	})

	vcJwts := []string{vc1, vc2, vc3}

	// Create capability chains
	chains := []auth.CapChainRef{
		{
			Kind:   auth.CapKindResource,
			Anchor: resourceURN,
			LeafID: "urn:vc:cap:VC2",
		},
	}

	// Create CapChainPresentation
	token, err := authInstance.CreateCapChainPresentation(
		context.Background(),
		vcJwts,
		holderDID,
		issuerDID,
		chains,
		provider.WithPrivateKey(privateKey),
	)

	if err != nil {
		t.Fatalf("CreateCapChainPresentation failed: %v", err)
	}

	// Verify VP Context
	vpCtx, err := authInstance.VerifyVPContext(context.Background(), token)
	if err != nil {
		t.Fatalf("VerifyVPContext failed: %v", err)
	}

	// Verify context fields
	if vpCtx.HolderDID != holderDID {
		t.Errorf("expected holderDID %s, got %s", holderDID, vpCtx.HolderDID)
	}

	if vpCtx.AudienceDID != issuerDID {
		t.Errorf("expected audienceDID %s, got %s", issuerDID, vpCtx.AudienceDID)
	}

	if len(vpCtx.VCs) == 0 {
		t.Error("expected at least one VC in context")
	}

	if len(vpCtx.Chains) == 0 {
		t.Error("expected at least one chain in context")
	}

	// Verify VC2 is present
	vc2Parsed, ok := vpCtx.VCs["urn:vc:cap:VC2"]
	if !ok {
		t.Error("expected VC2 to be present in context")
	} else {
		if vc2Parsed.Subject != holderDID {
			t.Errorf("expected VC2 subject %s, got %s", holderDID, vc2Parsed.Subject)
		}
		if vc2Parsed.Capability.Kind != auth.CapKindDelegate {
			t.Errorf("expected VC2 kind delegate, got %s", vc2Parsed.Capability.Kind)
		}
	}
}

// TestCheckServiceCapability tests the ServiceCapability authorization check
func TestCheckServiceCapability(t *testing.T) {
	privateKeyHex := "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
	privateKey, err := hex.DecodeString(privateKeyHex)
	if err != nil {
		t.Fatalf("failed to decode private key: %v", err)
	}

	ethereumProvider := ethereum.NewEthereumProvider(privateKey)
	authInstance := auth.NewAuth(ethereumProvider, "https://auth-dev.pila.vn/api/v1/did")

	serviceDID := "did:svc:StorageX"
	holderDID := "did:app:A"

	// Create service capability VC
	vcService := createTestCapabilityVCJWT(t, serviceDID, holderDID, "urn:vc:cap:VC3", map[string]interface{}{
		"kind":    "service",
		"service": serviceDID,
		"actions": []string{"file.read", "file.write"},
	})

	vcJwts := []string{vcService}

	chains := []auth.CapChainRef{
		{
			Kind:   auth.CapKindService,
			Anchor: serviceDID,
			LeafID: "urn:vc:cap:VC3",
		},
	}

	// Create CapChainPresentation
	token, err := authInstance.CreateCapChainPresentation(
		context.Background(),
		vcJwts,
		holderDID,
		serviceDID,
		chains,
		provider.WithPrivateKey(privateKey),
	)

	if err != nil {
		t.Fatalf("CreateCapChainPresentation failed: %v", err)
	}

	// Verify VP Context
	vpCtx, err := authInstance.VerifyVPContext(context.Background(), token)
	if err != nil {
		t.Fatalf("VerifyVPContext failed: %v", err)
	}

	// Test successful authorization
	trustedIssuers := []string{serviceDID}
	result, err := authInstance.CheckServiceCapability(
		context.Background(),
		vpCtx,
		serviceDID,
		"file.read",
		trustedIssuers,
	)

	if err != nil {
		t.Fatalf("CheckServiceCapability failed: %v", err)
	}

	if !result.Authorized {
		t.Errorf("expected authorization to succeed, got: %s", result.Reason)
	}

	// Test failed authorization - wrong action
	result, err = authInstance.CheckServiceCapability(
		context.Background(),
		vpCtx,
		serviceDID,
		"file.delete",
		trustedIssuers,
	)

	if err != nil {
		t.Fatalf("CheckServiceCapability failed: %v", err)
	}

	if result.Authorized {
		t.Error("expected authorization to fail for unauthorized action")
	}

	// Test failed authorization - wrong service
	result, err = authInstance.CheckServiceCapability(
		context.Background(),
		vpCtx,
		"did:svc:OtherService",
		"file.read",
		trustedIssuers,
	)

	if err != nil {
		t.Fatalf("CheckServiceCapability failed: %v", err)
	}

	if result.Authorized {
		t.Error("expected authorization to fail for wrong service")
	}
}

// TestCheckResourceCapabilityChain tests the ResourceCapabilityChain authorization check
func TestCheckResourceCapabilityChain(t *testing.T) {
	privateKeyHex := "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
	privateKey, err := hex.DecodeString(privateKeyHex)
	if err != nil {
		t.Fatalf("failed to decode private key: %v", err)
	}

	ethereumProvider := ethereum.NewEthereumProvider(privateKey)
	authInstance := auth.NewAuth(ethereumProvider, "https://auth-dev.pila.vn/api/v1/did")

	resourceURN := "urn:storagex:file:FILE_ID"
	holderDID := "did:app:A"

	// Create capability chain: VC0 (root) -> VC1 -> VC2 (leaf)
	vc0 := createTestCapabilityVCJWT(t, "did:svc:StorageX", "did:user:L", "urn:vc:cap:VC0", map[string]interface{}{
		"kind":     "resource",
		"resource": resourceURN,
		"actions":  []string{"read", "write"},
	})

	vc1 := createTestCapabilityVCJWT(t, "did:user:L", "did:user:H", "urn:vc:cap:VC1", map[string]interface{}{
		"kind":     "delegate",
		"resource": resourceURN,
		"actions":  []string{"read"},
		"parent":   "urn:vc:cap:VC0",
	})

	vc2 := createTestCapabilityVCJWT(t, "did:user:H", holderDID, "urn:vc:cap:VC2", map[string]interface{}{
		"kind":     "delegate",
		"resource": resourceURN,
		"actions":  []string{"read"},
		"parent":   "urn:vc:cap:VC1",
	})

	vcJwts := []string{vc0, vc1, vc2}

	chains := []auth.CapChainRef{
		{
			Kind:   auth.CapKindResource,
			Anchor: resourceURN,
			LeafID: "urn:vc:cap:VC2",
		},
	}

	// Create CapChainPresentation
	token, err := authInstance.CreateCapChainPresentation(
		context.Background(),
		vcJwts,
		holderDID,
		"did:svc:StorageX",
		chains,
		provider.WithPrivateKey(privateKey),
	)

	if err != nil {
		t.Fatalf("CreateCapChainPresentation failed: %v", err)
	}

	// Verify VP Context
	vpCtx, err := authInstance.VerifyVPContext(context.Background(), token)
	if err != nil {
		t.Fatalf("VerifyVPContext failed: %v", err)
	}

	// Test successful authorization
	result, err := authInstance.CheckResourceCapabilityChain(
		context.Background(),
		vpCtx,
		resourceURN,
		"read",
	)

	if err != nil {
		t.Fatalf("CheckResourceCapabilityChain failed: %v", err)
	}

	if !result.Authorized {
		t.Errorf("expected authorization to succeed, got: %s", result.Reason)
	}

	// Test failed authorization - wrong action
	result, err = authInstance.CheckResourceCapabilityChain(
		context.Background(),
		vpCtx,
		resourceURN,
		"write",
	)

	if err != nil {
		t.Fatalf("CheckResourceCapabilityChain failed: %v", err)
	}

	if result.Authorized {
		t.Error("expected authorization to fail for unauthorized action (attenuation)")
	}

	// Test failed authorization - wrong resource
	result, err = authInstance.CheckResourceCapabilityChain(
		context.Background(),
		vpCtx,
		"urn:storagex:file:OTHER_FILE",
		"read",
	)

	if err != nil {
		t.Fatalf("CheckResourceCapabilityChain failed: %v", err)
	}

	if result.Authorized {
		t.Error("expected authorization to fail for wrong resource")
	}
}

// TestCheckResourceCapabilityChainAttenuation tests attenuation rule enforcement
func TestCheckResourceCapabilityChainAttenuation(t *testing.T) {
	privateKeyHex := "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
	privateKey, err := hex.DecodeString(privateKeyHex)
	if err != nil {
		t.Fatalf("failed to decode private key: %v", err)
	}

	ethereumProvider := ethereum.NewEthereumProvider(privateKey)
	authInstance := auth.NewAuth(ethereumProvider, "https://auth-dev.pila.vn/api/v1/did")

	resourceURN := "urn:storagex:file:FILE_ID"
	holderDID := "did:app:A"

	// Create invalid chain where child has more actions than parent (violates attenuation)
	vc0 := createTestCapabilityVCJWT(t, "did:svc:StorageX", "did:user:L", "urn:vc:cap:VC0", map[string]interface{}{
		"kind":     "resource",
		"resource": resourceURN,
		"actions":  []string{"read"}, // Parent only has read
	})

	vc1 := createTestCapabilityVCJWT(t, "did:user:L", holderDID, "urn:vc:cap:VC1", map[string]interface{}{
		"kind":     "delegate",
		"resource": resourceURN,
		"actions":  []string{"read", "write"}, // Child has read+write (violation!)
		"parent":   "urn:vc:cap:VC0",
	})

	vcJwts := []string{vc0, vc1}

	chains := []auth.CapChainRef{
		{
			Kind:   auth.CapKindResource,
			Anchor: resourceURN,
			LeafID: "urn:vc:cap:VC1",
		},
	}

	// Create CapChainPresentation
	token, err := authInstance.CreateCapChainPresentation(
		context.Background(),
		vcJwts,
		holderDID,
		"did:svc:StorageX",
		chains,
		provider.WithPrivateKey(privateKey),
	)

	if err != nil {
		t.Fatalf("CreateCapChainPresentation failed: %v", err)
	}

	// Verify VP Context
	vpCtx, err := authInstance.VerifyVPContext(context.Background(), token)
	if err != nil {
		t.Fatalf("VerifyVPContext failed: %v", err)
	}

	// Test that attenuation violation is caught
	result, err := authInstance.CheckResourceCapabilityChain(
		context.Background(),
		vpCtx,
		resourceURN,
		"write",
	)

	if err != nil {
		t.Fatalf("CheckResourceCapabilityChain failed: %v", err)
	}

	if result.Authorized {
		t.Error("expected authorization to fail due to attenuation violation")
	}

	if result.Reason == "" {
		t.Error("expected reason for denial")
	}
}
