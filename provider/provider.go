package provider

// Provider defines the signing capability used by the auth service.
// Sign should take an arbitrary payload and return the signed token bytes.
type Provider interface {
	Sign(payload []byte, opts ...any) ([]byte, error)
}
