package vault

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// StorePrivateKeyResponse represents the Vault API response
type StorePrivateKeyResponse struct {
	RequestID     string              `json:"request_id"`
	LeaseID       string              `json:"lease_id"`
	Renewable     bool                `json:"renewable"`
	LeaseDuration int                 `json:"lease_duration"`
	Data          StorePrivateKeyData `json:"data"`
	WrapInfo      interface{}         `json:"wrap_info"`
	Warnings      interface{}         `json:"warnings"`
	Auth          interface{}         `json:"auth"`
	MountType     string              `json:"mount_type"`
}

// Constants for HTTP settings
const (
	contentTypeJSON   = "application/json"
	acceptHeader      = "*/*"
	defaultTimeout    = 10 * time.Second
	defaultMaxRetries = 3
)

// Vault holds the configuration for the Vault endpoint
type Vault struct {
	Address    string // Vault server address (e.g., http://109.237.70.93:8200)
	Token      string // Vault authentication token
	MaxRetries int    // Maximum number of retries for HTTP requests
	httpClient *http.Client
}

// NewVault initializes a new Vault instance with the specified address, token, and optional max retries
func NewVault(address, token string, maxRetries ...int) *Vault {
	retries := defaultMaxRetries
	if len(maxRetries) > 0 && maxRetries[0] >= 0 {
		retries = maxRetries[0]
	}

	return &Vault{
		Address:    address,
		Token:      token,
		MaxRetries: retries,
		httpClient: newHTTPClient(),
	}
}

func newHTTPClient() *http.Client {
	return &http.Client{
		Timeout: defaultTimeout,
	}
}

// StorePrivateKey sends a private key to the Vault ethsign accounts endpoint and returns the associated address
func (v *Vault) StorePrivateKey(ctx context.Context, privateKey string) (string, error) {
	// Create request payload
	reqBody := &StorePrivateKeyRequest{
		PrivateKey: privateKey,
	}

	jsonBody, err := json.Marshal(reqBody)
	if err != nil {
		return "", fmt.Errorf("failed to marshal request body: %w", err)
	}

	// Construct endpoint URL
	endpoint := v.Address + "/v1/secp/accounts"

	for attempt := 0; attempt <= v.MaxRetries; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewBuffer(jsonBody))
		if err != nil {
			return "", fmt.Errorf("failed to create request: %w", err)
		}

		req.Header.Set("Content-Type", contentTypeJSON)
		req.Header.Set("X-Vault-Token", v.Token)

		resp, err := v.httpClient.Do(req)
		if err != nil {
			return "", fmt.Errorf("failed to send request: %w", err)
		}

		defer func() {
			if cerr := resp.Body.Close(); cerr != nil {
				fmt.Printf("failed to close response body: %v\n", cerr)
			}
		}()

		if (resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode == http.StatusServiceUnavailable) && attempt < v.MaxRetries {
			select {
			case <-ctx.Done():
				return "", ctx.Err()
			case <-time.After(time.Duration(attempt+1) * time.Second):
				continue
			}
		}

		if resp.StatusCode != http.StatusOK {
			return "", fmt.Errorf("unexpected status code: %d", resp.StatusCode)
		}

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return "", fmt.Errorf("failed to read response body: %w", err)
		}

		var response StorePrivateKeyResponse
		if err := json.Unmarshal(body, &response); err != nil {
			return "", fmt.Errorf("failed to decode response: %w", err)
		}

		return response.Data.Address, nil
	}

	return "", fmt.Errorf("max retries exceeded for request")
}

// SignMessage signs a message using the Vault ethsign endpoint and returns the signed message
//
// - payload: 32 bytes hash of the message
//
// - address: hexa string with 0x prefix of the address
//
// - return: 64 bytes signature
func (v *Vault) SignMessage(ctx context.Context, payload []byte, address string) ([]byte, error) {
	if len(payload) != 32 {
		return nil, fmt.Errorf("payload must be 32 bytes")
	}

	if len(address) != 42 {
		return nil, fmt.Errorf("address must be 42 characters")
	}

	// Create request payload
	reqBody := &SignMessageRequest{Payload: "0x" + hex.EncodeToString(payload)}

	jsonBody, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	// Construct endpoint URL
	endpoint := v.Address + "/v1/secp/accounts/" + address + "/signRaw"

	for attempt := 0; attempt <= v.MaxRetries; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewBuffer(jsonBody))
		if err != nil {
			return nil, fmt.Errorf("failed to create request: %w", err)
		}

		req.Header.Set("Content-Type", contentTypeJSON)
		req.Header.Set("X-Vault-Token", v.Token)
		req.Header.Set("Accept", acceptHeader)
		req.Header.Set("Host", v.Address)
		req.Header.Set("Content-Length", fmt.Sprintf("%d", len(jsonBody)))

		resp, err := v.httpClient.Do(req)
		if err != nil {
			return nil, fmt.Errorf("failed to send request: %w", err)
		}
		defer resp.Body.Close()

		// Read response body for error details
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("failed to read response: %w", err)
		}

		if (resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode == http.StatusServiceUnavailable) && attempt < defaultMaxRetries {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(time.Duration(attempt+1) * time.Second):
				continue
			}
		}

		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("unexpected status code: %d, response body: %s", resp.StatusCode, string(body))
		}

		var response SignMessageResponse
		if err := json.Unmarshal(body, &response); err != nil {
			return nil, fmt.Errorf("failed to decode response: %w, response body: %s", err, string(body))
		}

		signatureBytes, err := hex.DecodeString(response.Data.Signed[2:])
		if err != nil {
			return nil, fmt.Errorf("failed to decode response: %w, response body: %s", err, string(body))
		}

		return signatureBytes[:64], nil
	}

	return nil, fmt.Errorf("max retries exceeded")
}
