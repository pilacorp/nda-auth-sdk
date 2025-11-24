package auth

import (
	"encoding/json"
	"errors"
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
