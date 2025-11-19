package auth

import (
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

// VcClaims represents the claims for a Verifiable Credential.
type VcClaims struct {
	Issuer            string         `json:"issuer"`
	CredentialSubject map[string]any `json:"credentialSubject"`
}
