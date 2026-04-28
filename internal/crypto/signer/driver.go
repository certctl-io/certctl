package signer

import "context"

// Driver knows how to materialize a Signer from some external reference
// (a file path, a PKCS#11 URI, a cloud KMS key ID, etc.) and how to
// generate a fresh key with a given algorithm.
//
// Drivers are responsible for any side-effect storage: FileDriver writes
// generated keys to disk via the keystore.ensureKeyDirSecure +
// keymem.marshalPrivateKeyAndZeroize discipline (injected via the
// FileDriver's hooks); future PKCS11Driver delegates key generation to
// the token; cloud-KMS drivers call the provider API.
//
// All Driver methods take a context.Context for cancellation/deadline
// propagation. Drivers MUST honor ctx.Done() for any I/O they perform;
// purely-in-memory drivers (MemoryDriver) may return immediately
// regardless of ctx state.
//
// Adding a new driver does NOT require changing this interface or any
// existing driver. The driver lives in its own package
// (internal/crypto/signer/<name>) and is constructed by a typed
// factory (e.g., pkcs11.New(config)).
type Driver interface {
	// Load resolves an existing key from ref and returns a Signer.
	// ref interpretation is driver-specific:
	//
	//   - FileDriver: filesystem path to a PEM-encoded private key
	//   - PKCS11Driver (future): pkcs11: URI per RFC 7512
	//   - CloudKMSDriver (future): provider-specific resource name
	//
	// Drivers MUST NOT log the contents of the loaded key (only the
	// ref + Algorithm). Callers wrap the returned Signer's Sign method
	// in their own logging if they need per-signature audit trail.
	Load(ctx context.Context, ref string) (Signer, error)

	// Generate creates a new key with the given algorithm and persists
	// it to driver-specific storage (or in-memory for MemoryDriver).
	// Returns a Signer wrapping the new key plus a ref string the
	// caller passes to a subsequent Load call (e.g., the file path
	// for FileDriver, the PKCS#11 URI for PKCS11Driver).
	//
	// If alg is not in the supported enum, Generate returns
	// ErrUnsupportedAlgorithm without side effects (no file written,
	// no token slot consumed).
	Generate(ctx context.Context, alg Algorithm) (Signer, string, error)

	// Name returns a stable identifier for the driver type. Used in
	// structured logs and (eventually) in CRL distribution-point URLs
	// when the URL embeds the signer kind. MUST be a single
	// lowercase token without spaces ("file", "memory", "pkcs11",
	// "aws-kms", "gcp-kms", "azure-kv").
	Name() string
}
