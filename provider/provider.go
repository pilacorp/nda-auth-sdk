package provider

import "context"

type ProviderOption struct {
	SignerAddress string
	CustomData    map[string]any
}

func (o *ProviderOption) WithSignerAddress(address string) {
	o.SignerAddress = address
}

func (o *ProviderOption) WithCustomData(data map[string]any) {
	o.CustomData = data
}

// Provider defines the signing capability used by the auth service.
// Sign should take an arbitrary payload and return the signed token bytes.
type Provider interface {
	Sign(ctx context.Context, payload []byte, options *ProviderOption) ([]byte, error)
}
