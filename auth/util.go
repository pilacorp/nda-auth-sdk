package auth

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// extractAddressFromDID extracts the Ethereum address from a DID string.
// It returns the substring after the last colon.
// Example: "did:nda:testnet:0x8b3b1dee8e00cb95f8b2a1d1a9a7cb8fe7d490ce" -> "0x8b3b1dee8e00cb95f8b2a1d1a9a7cb8fe7d490ce"
func ExtractAddressFromDID(did string) string {
	lastColonIndex := strings.LastIndex(did, ":")
	if lastColonIndex == -1 {
		return did // Return original string if no colon found
	}
	return did[lastColonIndex+1:]
}

// ParseVcClaimsWithStructs parses each VcClaim using corresponding struct from targets
// targets should be pointers to structs (e.g., &UserCredential{}, &CompanyCredential{})
func ParseVcClaimsWithStructs(vcClaims []map[string]any, targets []any) error {
	if len(vcClaims) != len(targets) {
		return errors.New("length of vcClaims and targets must be the same")
	}

	for i, claim := range vcClaims {
		// Convert map to JSON bytes
		jsonBytes, err := json.Marshal(claim)
		if err != nil {
			return errors.New("failed to marshal claim to JSON: " + err.Error())
		}

		// Unmarshal into user's struct (must be a pointer)
		if err := json.Unmarshal(jsonBytes, targets[i]); err != nil {
			return errors.New("failed to unmarshal JSON to struct: " + err.Error())
		}
	}

	return nil
}

// parseCapabilityVC parses a VC JWT and extracts CapVC information
func parseCapabilityVC(vcJwt string) (*CapVC, error) {
	// Parse JWT to extract payload directly
	parts := strings.Split(vcJwt, ".")
	if len(parts) != 3 {
		return nil, errors.New("invalid JWT format")
	}

	// Decode payload (base64url)
	payload := parts[1]
	// Add padding if needed
	if len(payload)%4 != 0 {
		payload += strings.Repeat("=", 4-len(payload)%4)
	}

	payloadBytes, err := base64.URLEncoding.DecodeString(payload)
	if err != nil {
		return nil, err
	}

	var jwtClaims map[string]any
	if err := json.Unmarshal(payloadBytes, &jwtClaims); err != nil {
		return nil, err
	}

	// Extract JWT claims (iss, sub, jti, nbf, exp)
	issuer, _ := jwtClaims["iss"].(string)
	subject, _ := jwtClaims["sub"].(string)
	jti, _ := jwtClaims["jti"].(string)

	// Parse time fields
	var nbf time.Time
	var exp time.Time
	if nbfVal, ok := jwtClaims["nbf"].(float64); ok && nbfVal > 0 {
		nbf = time.Unix(int64(nbfVal), 0)
	}
	if expVal, ok := jwtClaims["exp"].(float64); ok && expVal > 0 {
		exp = time.Unix(int64(expVal), 0)
	}

	// Extract VC data
	vcData, ok := jwtClaims["vc"].(map[string]any)
	if !ok {
		return nil, errors.New("missing vc field in JWT payload")
	}

	// Extract credentialSubject
	credSubject, ok := vcData["credentialSubject"].(map[string]any)
	if !ok {
		return nil, errors.New("missing credentialSubject in VC")
	}

	// Extract capability (cap) from credentialSubject
	capData, ok := credSubject["cap"].(map[string]any)
	if !ok {
		return nil, errors.New("missing cap field in credentialSubject")
	}

	capability := Capability{}

	// Parse kind
	if kindStr, ok := capData["kind"].(string); ok {
		capability.Kind = CapabilityKind(kindStr)
	}

	// Parse actions
	if actionsRaw, ok := capData["actions"].([]any); ok {
		actions := make([]string, len(actionsRaw))
		for i, a := range actionsRaw {
			if actionStr, ok := a.(string); ok {
				actions[i] = actionStr
			}
		}
		capability.Actions = actions
	}

	// Parse resource
	if resource, ok := capData["resource"].(string); ok {
		capability.Resource = resource
	}

	// Parse service
	if service, ok := capData["service"].(string); ok {
		capability.Service = service
	}

	// Parse onBehalfOf
	if onBehalfOf, ok := capData["onBehalfOf"].(string); ok {
		capability.OnBehalfOf = onBehalfOf
	}

	// Parse parent
	if parent, ok := capData["parent"].(string); ok {
		capability.Parent = parent
	}

	return &CapVC{
		ID:         jti,
		Issuer:     issuer,
		Subject:    subject,
		NotBefore:  nbf,
		ExpiresAt:  exp,
		Capability: capability,
	}, nil
}

// containsString checks if a string slice contains a specific string
func containsString(slice []string, str string) bool {
	for _, s := range slice {
		if s == str {
			return true
		}
	}
	return false
}

// isSubset checks if slice1 is a subset of slice2
func isSubset(slice1, slice2 []string) bool {
	for _, s1 := range slice1 {
		found := false
		for _, s2 := range slice2 {
			if s1 == s2 {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

// validateCapabilityStructure validates a capability structure according to DID-CapChain spec
func validateCapabilityStructure(cap Capability) error {
	// Validate kind
	if cap.Kind != CapKindResource && cap.Kind != CapKindDelegate && cap.Kind != CapKindService {
		return errors.New("invalid capability kind: " + string(cap.Kind))
	}

	// Resource capability must have resource
	if cap.Kind == CapKindResource {
		if cap.Resource == "" {
			return errors.New("resource capability must have resource field")
		}
		if cap.Service != "" {
			return errors.New("resource capability cannot have service field")
		}
	}

	// Service capability must have service
	if cap.Kind == CapKindService {
		if cap.Service == "" {
			return errors.New("service capability must have service field")
		}
		if cap.Resource != "" {
			return errors.New("service capability cannot have resource field")
		}
		if cap.Parent != "" {
			return errors.New("service capability cannot have parent field")
		}
	}

	// Delegate capability must have parent
	if cap.Kind == CapKindDelegate {
		if cap.Parent == "" {
			return errors.New("delegate capability must have parent field")
		}
		if cap.Service != "" {
			return errors.New("delegate capability cannot have service field")
		}
	}

	// Actions must not be empty
	if len(cap.Actions) == 0 {
		return errors.New("capability must have at least one action")
	}

	return nil
}

// validateCapabilityChains validates capability chains consistency
func validateCapabilityChains(chains []CapChainRef, vcMap map[string]CapVC, holderDID string) error {
	for _, chain := range chains {
		// Check that leaf VC exists
		leafVC, ok := vcMap[chain.LeafID]
		if !ok {
			return fmt.Errorf("leaf VC %s not found in provided VCs", chain.LeafID)
		}

		// Validate leaf VC belongs to holder
		if leafVC.Subject != holderDID {
			return fmt.Errorf("leaf VC %s subject (%s) does not match holder DID (%s)", chain.LeafID, leafVC.Subject, holderDID)
		}

		// Validate chain kind matches VC kind
		if chain.Kind != leafVC.Capability.Kind {
			// Exception: resource chains can have delegate leafs
			if chain.Kind == CapKindResource && leafVC.Capability.Kind == CapKindDelegate {
				// This is valid - delegate VC in resource chain
			} else if chain.Kind == CapKindService && leafVC.Capability.Kind == CapKindService {
				// Service chain must have service capability
			} else {
				return fmt.Errorf("chain kind (%s) does not match leaf VC kind (%s)", chain.Kind, leafVC.Capability.Kind)
			}
		}

		// For resource chains, validate anchor matches
		if chain.Kind == CapKindResource {
			if leafVC.Capability.Resource != chain.Anchor {
				return fmt.Errorf("chain anchor (%s) does not match leaf VC resource (%s)", chain.Anchor, leafVC.Capability.Resource)
			}
		}

		// For service chains, validate anchor matches
		if chain.Kind == CapKindService {
			if leafVC.Capability.Service != chain.Anchor {
				return fmt.Errorf("chain anchor (%s) does not match leaf VC service (%s)", chain.Anchor, leafVC.Capability.Service)
			}
		}

		// For resource chains with delegate leaf, validate parent chain exists
		if chain.Kind == CapKindResource && leafVC.Capability.Kind == CapKindDelegate {
			// Check that parent VC exists (should be in vcMap if full chain provided)
			if leafVC.Capability.Parent != "" {
				// Note: parent VC might not be in presentation if it's a root VC stored elsewhere
				// This is acceptable for now - parent will be validated during authorization phase
				_ = vcMap // Keep vcMap in scope for potential future validation
			}
		}
	}

	return nil
}
