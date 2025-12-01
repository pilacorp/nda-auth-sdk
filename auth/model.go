package auth

import (
	"time"

	"github.com/pilacorp/go-credential-sdk/credential/vc"
	"github.com/pilacorp/go-credential-sdk/credential/vp"
)

// CredentialContent represents the credential content for token creation
type CredentialContent struct {
	Credential vc.CredentialContents `json:"credential"`
}

// PresentationContents represents the presentation contents for token creation
type PresentationContents struct {
	Presentation vp.PresentationContents `json:"presentation"`
}

// CapabilityKind represents the type of capability
type CapabilityKind string

const (
	CapKindResource CapabilityKind = "resource"
	CapKindDelegate CapabilityKind = "delegate"
	CapKindService  CapabilityKind = "service"
)

// Capability represents a capability with its attributes
type Capability struct {
	Kind       CapabilityKind `json:"kind"`
	Resource   string         `json:"resource,omitempty"`
	Service    string         `json:"service,omitempty"`
	Actions    []string       `json:"actions,omitempty"`
	OnBehalfOf string         `json:"onBehalfOf,omitempty"`
	Parent     string         `json:"parent,omitempty"`
}

// CapVC represents a parsed Capability Credential (VC)
type CapVC struct {
	ID         string     `json:"id"`        // jti
	Issuer     string     `json:"issuer"`    // iss
	Subject    string     `json:"subject"`   // sub
	NotBefore  time.Time  `json:"notBefore"` // nbf
	ExpiresAt  time.Time  `json:"expiresAt"` // exp
	Capability Capability `json:"capability"`
}

// CapChainRef represents a capability chain reference in VP
type CapChainRef struct {
	Kind   CapabilityKind `json:"kind"`
	Anchor string         `json:"anchor"`
	LeafID string         `json:"leaf"`
}

// VerifiedVPContext is the output of the Verification Phase
type VerifiedVPContext struct {
	HolderDID   string           `json:"holderDID"`
	AudienceDID string           `json:"audienceDID"`
	VCs         map[string]CapVC `json:"vcs"`    // map of VC ID -> CapVC
	Chains      []CapChainRef    `json:"chains"` // capability chain references
}

// AuthorizationResult represents the result of an authorization check
type AuthorizationResult struct {
	Authorized bool   `json:"authorized"`
	Reason     string `json:"reason,omitempty"`
}
