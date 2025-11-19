package provider

import "context"

type SignOptions struct {
	SignerAddress string
	PrivateKey    []byte
	CustomData    map[string]any
}

type SignOption func(*SignOptions)

func WithSignerAddress(address string) SignOption {
	return func(o *SignOptions) {
		o.SignerAddress = address
	}
}

func WithCustomData(data map[string]any) SignOption {
	return func(o *SignOptions) {
		o.CustomData = data
	}
}

func WithPrivateKey(privateKey []byte) SignOption {
	return func(o *SignOptions) {
		o.PrivateKey = privateKey
	}
}

// Provider defines the signing capability used by the auth service.
// Sign should take an arbitrary payload and return the signed token bytes.
type Provider interface {
	Sign(ctx context.Context, payload []byte, opts ...SignOption) ([]byte, error)
}
