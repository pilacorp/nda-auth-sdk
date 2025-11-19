package vault

type SignMessageRequest struct {
	Payload string `json:"payload"`
}

// SignMessageResponse represents the Vault API response for signing a message
type SignMessageResponse struct {
	Data struct {
		Signed string `json:"signature"`
	} `json:"data"`
}

// StorePrivateKeyRequest represents the JSON payload for storing a private key
type StorePrivateKeyRequest struct {
	PrivateKey string `json:"privateKey"`
}

// StorePrivateKeyData contains the address field from the response
type StorePrivateKeyData struct {
	Address string `json:"address"`
}
