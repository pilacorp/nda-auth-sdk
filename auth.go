package auth

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"

	"github.com/pilacorp/nda-auth-sdk/provider"

	vcdto "github.com/pilacorp/go-credential-sdk/credential/common/dto"
	"github.com/pilacorp/go-credential-sdk/credential/vc"
	"github.com/pilacorp/go-credential-sdk/credential/vp"
)

type Auth interface {
	// CreateToken creates a new VP token with a list of VCs.
	CreateToken(ctx context.Context, vcsJwt []string, holderDid string) (string, error)

	// VerifyToken verifies a VP token with a list of VCs.
	VerifyToken(ctx context.Context, token string) ([]VcClaims, error)

	// VerifyTokenWithStructs verifies a VP token with a list of VCs and parses the claims into a list of structs.
	VerifyTokenWithStructs(ctx context.Context, token string, targets []any) error
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

// CreateToken creates a new VP token with a list of VCs.
func (a *auth) CreateToken(ctx context.Context, vcsJwt []string, holderDid string) (string, error) {
	vcs := make([]vc.Credential, len(vcsJwt))
	for i, vcJwt := range vcsJwt {
		vc, err := vc.ParseCredential([]byte(vcJwt))
		if err != nil {
			return "", err
		}

		vcs[i] = vc
	}

	vpContents := vp.PresentationContents{
		Context: []any{
			"https://www.w3.org/ns/credentials/v2",
			"https://www.w3.org/ns/credentials/examples/v2",
		},
		Holder:                holderDid,
		Types:                 []string{"VerifiablePresentation"},
		VerifiableCredentials: vcs,
	}

	vpPresentation, err := vp.NewJWTPresentation(vpContents)
	if err != nil {
		return "", err
	}

	signData, err := vpPresentation.GetSigningInput()
	if err != nil {
		return "", err
	}

	hash := sha256.Sum256(signData)
	signature, err := a.provider.Sign(hash[:], ExtractAddressFromDID(holderDid))
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

	documentBytes, err := json.Marshal(document)
	if err != nil {
		return "", err
	}

	return string(documentBytes), nil
}

// VerifyToken verifies a VP token with a list of VCs.
func (a *auth) VerifyToken(ctx context.Context, token string) ([]VcClaims, error) {
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

	// Extract verifiableCredential array
	vcsRaw, ok := vpData["verifiableCredential"]
	if !ok {
		return nil, errors.New("no verifiableCredential found in VP")
	}

	vcsArray, ok := vcsRaw.([]any)
	if !ok {
		return nil, errors.New("verifiableCredential is not an array")
	}

	// Parse each VC and extract CredentialContents
	var vcClaimsList []VcClaims
	for _, vcItem := range vcsArray {
		var credential vc.Credential
		var err error

		credential, err = vc.ParseCredential([]byte(vcItem.(string)))

		if err != nil {
			return nil, err
		}

		// Get credential contents
		credContentsBytes, err := credential.GetContents()
		if err != nil {
			return nil, err
		}

		var credContents map[string]any
		if err := json.Unmarshal(credContentsBytes, &credContents); err != nil {
			return nil, err
		}

		vcClaimsList = append(vcClaimsList, VcClaims{
			Issuer:            credContents["issuer"].(string),
			CredentialSubject: credContents["credentialSubject"].(map[string]any),
		})
	}

	return vcClaimsList, nil
}

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
