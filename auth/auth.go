package auth

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	vcdto "github.com/pilacorp/go-credential-sdk/credential/common/dto"
	"github.com/pilacorp/go-credential-sdk/credential/vc"
	"github.com/pilacorp/go-credential-sdk/credential/vp"
	"github.com/pilacorp/nda-auth-sdk/provider"
)

type Auth interface {
	// VerifyTokenWithStructs verifies a VP token with a list of VCs and parses the claims into a list of structs.
	VerifyTokenWithStructs(ctx context.Context, token string, targets []any) error

	// CreateCapChainPresentation creates a CapChainPresentation (DID-CapChain VP) with capability chains metadata.
	// If chains is nil or empty, creates a simple VP compatible with CreateToken for backward compatibility.
	CreateCapChainPresentation(
		ctx context.Context,
		vcsJwt []string, holderDid, audienceDid string,
		chains []CapChainRef, opts ...provider.SignOption) (string, error)

	// VerifyVPContext performs Verification Phase - validates VP/VC and returns VerifiedVPContext.
	VerifyVPContext(ctx context.Context, token string) (*VerifiedVPContext, error)

	// CheckServiceCapability performs ServiceCapability authorization check.
	CheckServiceCapability(
		ctx context.Context,
		vpCtx *VerifiedVPContext, serviceDID, action string,
		trustedIssuers []string,
	) (*AuthorizationResult, error)

	// CheckResourceCapabilityChain performs ResourceCapabilityChain authorization check with attenuation validation.
	CheckResourceCapabilityChain(
		ctx context.Context,
		vpCtx *VerifiedVPContext,
		resourceURN, action string,
	) (*AuthorizationResult, error)
}

type auth struct {
	provider provider.Provider
}

// NewAuth creates a new Auth instance.
// It initializes the VC and VP SDKs with the provided DID URL.
func NewAuth(p provider.Provider, didUrl string) Auth {
	vc.Init(didUrl)
	vp.Init(didUrl)
	return &auth{
		provider: p,
	}
}

// VerifyTokenWithStructs verifies a VP token and parses claims into structs.
func (a *auth) VerifyTokenWithStructs(ctx context.Context, token string, targets []any) error {
	vpPresentation, err := vp.ParseJWTPresentation(token, vp.WithVerifyProof(), vp.WithVCValidation())
	if err != nil {
		return err
	}

	// Get VP contents
	vpContentsBytes, err := vpPresentation.GetContents()
	if err != nil {
		return err
	}

	// Parse VP contents as JSON
	var vpData map[string]any
	if err := json.Unmarshal(vpContentsBytes, &vpData); err != nil {
		return err
	}

	// Extract verifiableCredential array
	vcsRaw, ok := vpData["verifiableCredential"]
	if !ok {
		return errors.New("no verifiableCredential found in VP")
	}

	vcsArray, ok := vcsRaw.([]any)
	if !ok {
		return errors.New("verifiableCredential is not an array")
	}

	vcClaimsList := make([]map[string]any, len(vcsArray))

	for i, vcItem := range vcsArray {
		var credential vc.Credential
		var err error

		credential, err = vc.ParseCredential([]byte(vcItem.(string)))
		if err != nil {
			return err
		}

		credContentsBytes, err := credential.GetContents()
		if err != nil {
			return err
		}

		var credContents map[string]any
		if err := json.Unmarshal(credContentsBytes, &credContents); err != nil {
			return err
		}

		// Flatten the structure: merge issuer and credentialSubject fields into top level
		vcClaimsList[i] = make(map[string]any)

		// Add issuer at top level
		if issuer, ok := credContents["issuer"]; ok {
			vcClaimsList[i]["issuer"] = issuer
		}

		// Flatten credentialSubject fields to top level
		if credentialSubject, ok := credContents["credentialSubject"].(map[string]any); ok {
			for k, v := range credentialSubject {
				vcClaimsList[i][k] = v
			}
		}
	}

	return ParseVcClaimsWithStructs(vcClaimsList, targets)
}

// CreateCapChainPresentation creates a CapChainPresentation (DID-CapChain VP) with capability chains metadata.
func (a *auth) CreateCapChainPresentation(ctx context.Context, vcsJwt []string, holderDid string, audienceDid string, chains []CapChainRef, opts ...provider.SignOption) (string, error) {
	// Validate all VCs before creating the presentation
	vcs := make([]vc.Credential, 0, len(vcsJwt))
	vcMap := make(map[string]CapVC) // Map of VC ID -> CapVC for validation

	for i, vcJwt := range vcsJwt {
		// Parse and validate VC signature
		parsedVC, err := vc.ParseCredential([]byte(vcJwt), vc.WithVerifyProof())
		if err != nil {
			return "", fmt.Errorf("invalid VC at index %d: %w", i, err)
		}

		// Validate VC structure and extract capability info
		capVC, err := parseCapabilityVC(vcJwt)
		if err != nil {
			return "", fmt.Errorf("failed to parse capability VC at index %d: %w", i, err)
		}

		// Validate VC expiration
		now := time.Now()
		if !capVC.NotBefore.IsZero() && now.Before(capVC.NotBefore) {
			return "", errors.New("VC " + capVC.ID + " is not yet valid (nbf: " + capVC.NotBefore.Format(time.RFC3339) + ")")
		}
		if !capVC.ExpiresAt.IsZero() && now.After(capVC.ExpiresAt) {
			return "", errors.New("VC " + capVC.ID + " has expired (exp: " + capVC.ExpiresAt.Format(time.RFC3339) + ")")
		}

		// Validate capability structure
		if err := validateCapabilityStructure(capVC.Capability); err != nil {
			return "", errors.New("invalid capability structure in VC " + capVC.ID + ": " + err.Error())
		}

		vcs = append(vcs, parsedVC)
		vcMap[capVC.ID] = *capVC
	}

	// Validate capability chains consistency if provided
	if len(chains) > 0 {
		if err := validateCapabilityChains(chains, vcMap, holderDid); err != nil {
			return "", errors.New("invalid capability chains: " + err.Error())
		}
	}

	// Build VP with context (use DID-CapChain context if chains provided, otherwise simple VP context)
	contexts := []any{
		"https://www.w3.org/ns/credentials/v2",
	}
	types := []string{"VerifiablePresentation"}

	if len(chains) > 0 {
		// Add DID-CapChain context and type
		contexts = append(contexts, "https://did-capchain.org/contexts/capchain-v1")
		types = append(types, "CapChainPresentation")
	} else {
		// Use simple VP context for backward compatibility
		contexts = append(contexts, "https://www.w3.org/ns/credentials/examples/v2")
	}

	vpContents := vp.PresentationContents{
		Context:               contexts,
		Holder:                holderDid,
		Types:                 types,
		VerifiableCredentials: vcs,
	}

	vpPresentation, err := vp.NewJWTPresentation(vpContents)
	if err != nil {
		return "", err
	}

	// Add cap_chains to VP custom data
	vpContentsBytes, err := vpPresentation.GetContents()
	if err != nil {
		return "", err
	}

	var vpData map[string]any
	if err := json.Unmarshal(vpContentsBytes, &vpData); err != nil {
		return "", err
	}

	// Sign the VP
	signData, err := vpPresentation.GetSigningInput()
	if err != nil {
		return "", err
	}

	hash := sha256.Sum256(signData)
	signature, err := a.provider.Sign(ctx, hash[:], opts...)
	if err != nil {
		return "", err
	}

	err = vpPresentation.AddCustomProof(&vcdto.Proof{
		Signature: signature,
	})
	if err != nil {
		return "", err
	}

	document, err := vpPresentation.Serialize()
	if err != nil {
		return "", err
	}

	// Only add cap_chains and aud if provided (for backward compatibility)
	if len(chains) > 0 || audienceDid != "" {
		// Merge cap_chains into the serialized document
		var documentMap map[string]any

		// Handle document as map or bytes
		switch d := document.(type) {
		case map[string]any:
			documentMap = d
		case []byte:
			if err := json.Unmarshal(d, &documentMap); err != nil {
				return "", err
			}
		default:
			// Try to marshal/unmarshal to convert to map
			docBytes, err := json.Marshal(document)
			if err != nil {
				return "", err
			}
			if err := json.Unmarshal(docBytes, &documentMap); err != nil {
				return "", err
			}
		}

		// Add cap_chains to the vp object in the document if provided
		if len(chains) > 0 {
			if vpInDoc, ok := documentMap["vp"].(map[string]any); ok {
				vpInDoc["cap_chains"] = chains
				documentMap["vp"] = vpInDoc
			}
		}

		// Add aud to document if provided
		if audienceDid != "" {
			documentMap["aud"] = audienceDid
		}

		documentBytes, err := json.Marshal(documentMap)
		if err != nil {
			return "", err
		}

		return string(documentBytes), nil
	}

	// For backward compatibility (no chains, no audience), return as-is
	documentBytes, err := json.Marshal(document)
	if err != nil {
		return "", err
	}

	return string(documentBytes), nil
}

// VerifyVPContext performs Verification Phase - validates VP/VC and returns VerifiedVPContext.
func (a *auth) VerifyVPContext(ctx context.Context, token string) (*VerifiedVPContext, error) {
	vpPresentation, err := vp.ParseJWTPresentation(token, vp.WithVerifyProof(), vp.WithVCValidation())
	if err != nil {
		return nil, err
	}

	// Get VP contents
	vpContentsBytes, err := vpPresentation.GetContents()
	if err != nil {
		return nil, err
	}

	// Parse VP contents as JSON
	var vpData map[string]any
	if err := json.Unmarshal(vpContentsBytes, &vpData); err != nil {
		return nil, err
	}

	// Extract holder
	holder, ok := vpData["holder"].(string)
	if !ok {
		return nil, errors.New("no holder found in VP")
	}

	// Extract audience (aud)
	audience, _ := vpData["aud"].(string)

	// Extract cap_chains
	var chains []CapChainRef
	if vpObj, ok := vpData["vp"].(map[string]any); ok {
		if chainsRaw, ok := vpObj["cap_chains"].([]any); ok {
			for _, chainRaw := range chainsRaw {
				chainMap, ok := chainRaw.(map[string]any)
				if !ok {
					continue
				}
				chain := CapChainRef{
					Kind:   CapabilityKind(getString(chainMap, "kind")),
					Anchor: getString(chainMap, "anchor"),
					LeafID: getString(chainMap, "leaf"),
				}
				chains = append(chains, chain)
			}
		}
	}

	// Extract verifiableCredential array
	vcsRaw, ok := vpData["verifiableCredential"]
	if !ok {
		return nil, errors.New("no verifiableCredential found in VP")
	}

	vcsArray, ok := vcsRaw.([]any)
	if !ok {
		return nil, errors.New("verifiableCredential is not an array")
	}

	// Parse all VCs into CapVC map
	vcsMap := make(map[string]CapVC)
	for _, vcItem := range vcsArray {
		vcJwt, ok := vcItem.(string)
		if !ok {
			continue
		}

		capVC, err := parseCapabilityVC(vcJwt)
		if err != nil {
			// Skip invalid VCs, but log the error
			continue
		}

		vcsMap[capVC.ID] = *capVC
	}

	return &VerifiedVPContext{
		HolderDID:   holder,
		AudienceDID: audience,
		VCs:         vcsMap,
		Chains:      chains,
	}, nil
}

// getString safely extracts a string from a map
func getString(m map[string]any, key string) string {
	if val, ok := m[key].(string); ok {
		return val
	}
	return ""
}

// CheckServiceCapability performs ServiceCapability authorization check.
func (a *auth) CheckServiceCapability(ctx context.Context, vpCtx *VerifiedVPContext, serviceDID string, action string, trustedIssuers []string) (*AuthorizationResult, error) {
	// Find service capability chain
	var serviceChain *CapChainRef
	for i := range vpCtx.Chains {
		if vpCtx.Chains[i].Kind == CapKindService && vpCtx.Chains[i].Anchor == serviceDID {
			serviceChain = &vpCtx.Chains[i]
			break
		}
	}

	if serviceChain == nil {
		return &AuthorizationResult{
			Authorized: false,
			Reason:     "no service capability chain found for service",
		}, nil
	}

	// Get leaf VC
	leafVC, ok := vpCtx.VCs[serviceChain.LeafID]
	if !ok {
		return &AuthorizationResult{
			Authorized: false,
			Reason:     "leaf VC not found in verified context",
		}, nil
	}

	// Verify VC belongs to holder
	if leafVC.Subject != vpCtx.HolderDID {
		return &AuthorizationResult{
			Authorized: false,
			Reason:     "service capability VC subject does not match holder DID",
		}, nil
	}

	// Verify it's a service capability
	if leafVC.Capability.Kind != CapKindService {
		return &AuthorizationResult{
			Authorized: false,
			Reason:     "leaf VC is not a service capability",
		}, nil
	}

	// Verify service matches
	if leafVC.Capability.Service != serviceDID {
		return &AuthorizationResult{
			Authorized: false,
			Reason:     "service capability service does not match requested service",
		}, nil
	}

	// Verify action is allowed
	if !containsString(leafVC.Capability.Actions, action) {
		return &AuthorizationResult{
			Authorized: false,
			Reason:     "requested action not in capability actions",
		}, nil
	}

	// Verify issuer is trusted
	if len(trustedIssuers) > 0 {
		issuerTrusted := false
		for _, trustedIssuer := range trustedIssuers {
			if leafVC.Issuer == trustedIssuer {
				issuerTrusted = true
				break
			}
		}
		if !issuerTrusted {
			return &AuthorizationResult{
				Authorized: false,
				Reason:     "service capability issuer is not trusted",
			}, nil
		}
	}

	return &AuthorizationResult{
		Authorized: true,
	}, nil
}

// CheckResourceCapabilityChain performs ResourceCapabilityChain authorization check with attenuation validation.
func (a *auth) CheckResourceCapabilityChain(ctx context.Context, vpCtx *VerifiedVPContext, resourceURN string, action string) (*AuthorizationResult, error) {
	// Find resource capability chain
	var resourceChain *CapChainRef
	for i := range vpCtx.Chains {
		if vpCtx.Chains[i].Kind == CapKindResource && vpCtx.Chains[i].Anchor == resourceURN {
			resourceChain = &vpCtx.Chains[i]
			break
		}
	}

	if resourceChain == nil {
		return &AuthorizationResult{
			Authorized: false,
			Reason:     "no resource capability chain found for resource",
		}, nil
	}

	// Get leaf VC
	leafVC, ok := vpCtx.VCs[resourceChain.LeafID]
	if !ok {
		return &AuthorizationResult{
			Authorized: false,
			Reason:     "leaf VC not found in verified context",
		}, nil
	}

	// Verify VC belongs to holder
	if leafVC.Subject != vpCtx.HolderDID {
		return &AuthorizationResult{
			Authorized: false,
			Reason:     "resource capability VC subject does not match holder DID",
		}, nil
	}

	// Verify resource matches
	if leafVC.Capability.Resource != resourceURN {
		return &AuthorizationResult{
			Authorized: false,
			Reason:     "resource capability resource does not match requested resource",
		}, nil
	}

	// Verify action is allowed
	if !containsString(leafVC.Capability.Actions, action) {
		return &AuthorizationResult{
			Authorized: false,
			Reason:     "requested action not in leaf capability actions",
		}, nil
	}

	// Traverse chain backwards to root, applying attenuation rule
	currentVC := leafVC
	for {
		// Check if this is a root capability (no parent)
		if currentVC.Capability.Parent == "" {
			// Should be a ResourceCapabilityCredential (kind = resource)
			if currentVC.Capability.Kind != CapKindResource {
				return &AuthorizationResult{
					Authorized: false,
					Reason:     "root capability is not a ResourceCapabilityCredential",
				}, nil
			}
			// Reached root, chain is valid
			break
		}

		// Get parent VC
		parentVC, ok := vpCtx.VCs[currentVC.Capability.Parent]
		if !ok {
			return &AuthorizationResult{
				Authorized: false,
				Reason:     "parent VC not found in verified context",
			}, nil
		}

		// Verify parent resource matches
		if parentVC.Capability.Resource != resourceURN {
			return &AuthorizationResult{
				Authorized: false,
				Reason:     "parent capability resource does not match requested resource",
			}, nil
		}

		// Apply attenuation rule: actions(child) ⊆ actions(parent)
		if !isSubset(currentVC.Capability.Actions, parentVC.Capability.Actions) {
			return &AuthorizationResult{
				Authorized: false,
				Reason:     "attenuation rule violated: child actions are not a subset of parent actions",
			}, nil
		}

		// Verify delegation flow: parent.Subject == child.Issuer
		if parentVC.Subject != currentVC.Issuer {
			return &AuthorizationResult{
				Authorized: false,
				Reason:     "delegation flow violated: parent subject does not match child issuer",
			}, nil
		}

		// Move to parent
		currentVC = parentVC
	}

	return &AuthorizationResult{
		Authorized: true,
	}, nil
}
