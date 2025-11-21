package auth

import (
	"encoding/json"
	"fmt"
	"log"
	"strings"
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
		log.Fatalf("claims count (%d) must match targets count (%d)", len(vcClaims), len(targets))
	}

	for i, claim := range vcClaims {
		// Convert map to JSON bytes
		jsonBytes, err := json.Marshal(claim)
		if err != nil {
			log.Fatalf("marshal error at index %d: %v", i, err)
		}

		// Unmarshal into user's struct (must be a pointer)
		if err := json.Unmarshal(jsonBytes, targets[i]); err != nil {
			log.Fatalf("unmarshal error at index %d: %v", i, err)
		}
	}

	return nil
}

// convertVCItemToBytes converts a VC item (string or map) to bytes for parsing.
// It handles both JWT string format and already-parsed JSON map format.
func convertVCItemToBytes(vcItem any) ([]byte, error) {
	switch v := vcItem.(type) {
	case string:
		return []byte(v), nil
	case map[string]interface{}:
		vcBytes, err := json.Marshal(v)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal VC: %w", err)
		}
		return vcBytes, nil
	default:
		return nil, fmt.Errorf("unexpected VC type: %T", vcItem)
	}
}
