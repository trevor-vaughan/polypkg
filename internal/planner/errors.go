package planner

import "fmt"

// TrustRootError reports that a source's trust_root anchor file exists but is
// not a valid minisign public key. The planner is the only layer that knows the
// configured path, so it carries it here; the underlying library detail stays
// in the chain (Unwrap) for logs. The CLI frames the path-aware user message
// and the actionable hint.
type TrustRootError struct {
	Path string
	Err  error
}

func (e *TrustRootError) Error() string {
	return fmt.Sprintf("trust_root %s is not a valid minisign public key", e.Path)
}

func (e *TrustRootError) Unwrap() error { return e.Err }

// ArtifactSignatureError reports that an artifact failed signature
// verification. It deliberately omits the verifier's failure-mode detail (e.g.
// "Invalid signature" vs "signature does not match data") from its message:
// surfacing which check failed would only help an attacker probe the verifier.
// The underlying cause stays in the chain (Unwrap) for operator logs. The CLI
// frames the user message and the corruption/tampering hint.
type ArtifactSignatureError struct {
	Name    string
	Version string
	Source  string
	Err     error
}

func (e *ArtifactSignatureError) Error() string {
	return fmt.Sprintf("signature verification failed for %s-%s from source %q", e.Name, e.Version, e.Source)
}

func (e *ArtifactSignatureError) Unwrap() error { return e.Err }
