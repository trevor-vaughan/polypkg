# Embedded sigstore fixtures (copies)

`bindable-bundle.json`, `bindable-content.bin`, and `bindable-root.json` are
byte-for-byte copies of `internal/attest/testdata/`, `go:embed`ed by
`gen.go` so the host-side fixture generator is self-contained across the
`task provenance:fixtures` pre-step and the container matrix (no CWD-relative
path or cross-package `..` embed).

They are minted by `internal/attest/testdata/sigstoregen/main.go`
(`go run ./internal/attest/testdata/sigstoregen/main.go`). If that generator
is ever re-run, re-copy the three files here so both locations stay in sync.
