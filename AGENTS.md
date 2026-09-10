# AGENTS.md

Guidance for AI coding agents working in this repository. Claude Code loads it through the one-line `@AGENTS.md` import in `CLAUDE.md`.

## Overview

`step-kms-plugin` is a small Cobra CLI (module `github.com/smallstep/step-kms-plugin`, Apache-2.0) that creates keys, signs, encrypts/decrypts, and manages certificates on cloud KMSs, HSMs, TPMs, YubiKeys, and the macOS keychain. It runs standalone or as a `step` plugin: `step kms <cmd>` execs `step-kms-plugin <cmd>` with the same arguments. Nearly all KMS logic lives upstream in `go.step.sm/crypto/kms`; this repo is the CLI surface over that library. `main.go` blank-imports every KMS backend (`awskms`, `azurekms`, `capi`, `cloudkms`, `mackms`, `pkcs11`, `platform`, `softkms`, `sshagentkms`, `tpmkms`, `yubikey`) so they self-register.

## Commands

```bash
make build         # go build -> bin/step-kms-plugin (needs cgo + libpcsclite for pkcs11/yubikey)
make build-fips    # same with GOFIPS140 and -tags noyubikey
make test          # go test -coverprofile=coverage.out ./...
make lint          # golangci-lint (config fetched from smallstep/workflows) + govulncheck
make fmt           # goimports with --local for this module and go.step.sm/crypto
make generate      # go generate ./... then regenerate completions/* from the built binary
make bootstrap     # install golangci-lint, govulncheck, gotestsum
make release-dry-run  # goreleaser-cross-pro in Docker; needs GORELEASER_KEY
```

There are currently no `_test.go` files, so `make test` only compiles the packages (coverage reports 0%). `make build` takes about 20s cold on macOS with no extra setup. CI (`.github/workflows/ci.yml`) calls the shared `smallstep/workflows` `goCI.yml` with `os-dependencies: libpcsclite-dev`, `only-latest-golang: false`, and CodeQL enabled, so lint, vulncheck, and the build must pass on every supported Go version, not just the latest.

Run the binary locally with `bin/step-kms-plugin <cmd> <uri>` or, after putting it on `$PATH` or in `$(step path --base)/plugins`, as `step kms <cmd> <uri>`.

Cross-compiling with cgo (`.goreleaser.yml`) sets a per-target `CC`; `make build` on the host is the normal dev loop. `CGO_ENABLED=0` builds still work (see `docker/Dockerfile.cloud`) but drop pkcs11, yubikey, and the macOS keychain backends via the `!cgo` build files in `go.step.sm/crypto/kms/*`.

## Generated Code — Do Not Edit

| Pattern | Generator |
|---------|-----------|
| `completions/{bash,fish,powershell,zsh}_completion` | `make generate` (Cobra `completion` subcommand of the built binary); shipped in release archives and deb/rpm packages |

## Architecture

```
step-kms-plugin/
├── main.go                      # imports cmd + blank-imports all go.step.sm/crypto/kms backends
├── cmd/
│   ├── root.go                  # rootCmd, persistent --kms flag, openKMS(), URI helpers, PromptPassword hook
│   ├── create.go                # create <uri>: --kty/--crv/--size/--alg/--pss, YubiKey pin/touch policy, TPM AK/attest-by
│   ├── key.go, key_delete.go    # key <uri> (print public key), key delete
│   ├── certificate*.go          # certificate <uri> (print), certificate copy, certificate delete
│   ├── sign.go                  # sign <uri> [digest]: --in file, --alg, --pss, --format (base64/hex/jws/raw)
│   ├── encrypt.go, decrypt.go   # RSA-OAEP/PKCS#1 encrypt with a public key, decrypt with a KMS key
│   ├── attest.go                # attest <uri>: YubiKey/TPM attestation certs and ACME device-attest-01 objects
│   ├── search.go                # search <uri>: list keys in a KMS that implements SearchKeys (anonymous interface)
│   ├── ctk.go                   # darwin+cgo only: list CryptoTokenKit identities
│   └── version.go               # Version/ReleaseDate set via -ldflags -X (Makefile and goreleaser)
├── internal/
│   ├── flagutil/                # MustString/MustInt/MustBool + allow-listed pflag.Value helpers
│   ├── termutil/                # password prompt on the controlling terminal (borrowed from age)
│   └── darwin/{corefoundation,security}/  # cgo bindings to CoreFoundation and Security.framework (darwin+cgo)
├── completions/                 # generated shell completions
├── docker/                      # Dockerfile (alpine), .debian, .cloud (CGO_ENABLED=0), .wolfi (build-fips)
├── scripts/                     # package-upload.sh, package-repo-import.sh (goreleaser publisher hooks)
├── .goreleaser.yml              # cross builds (linux/darwin/windows), archives, nfpm deb/rpm, SBOMs
└── Makefile
```

### Command flow

Every command follows the same shape:

1. Validate positional args; on misuse return `showErrUsage(cmd)` so Cobra prints usage.
2. Read flags with `flagutil.Must*` (panics on a typo in the flag name, which is intentional: the flag must be defined in `init()`).
3. Resolve the KMS URI. The persistent `--kms <uri>` flag configures the backend; the positional `<uri>` names the key. `getURIAndNameForFS` / `openKMS` in `root.go` merge them, add the `:` scheme suffix if missing (`--kms tpmkms` works), and for `tpmkms:` inject `storage-directory=$(step path)/tpm` after calling `step.Init()` from `cli-utils`.
4. `kms.New(ctx, apiv1.Options{...})` returns an `apiv1.KeyManager`; commands type-assert the optional interfaces they need (`apiv1.CertificateManager`, `CertificateChainManager`, `Attester`, `Decrypter`, or an inline interface for `SearchKeys`) and return a clear error when the backend does not implement one.
5. Output goes to stdout as PEM (`outputCert`, `pemutil`) or `--json` where supported.

Adding a subcommand: new file in `cmd/`, define a `*cobra.Command`, register it in that file's `init()` with `rootCmd.AddCommand(...)` (or `certificateCmd`/`keyCmd` for nested commands), set `SilenceUsage = true` on commands that should not dump usage on runtime errors, then `make generate` to refresh completions.

## Conventions

- **CLI**: Cobra + pflag. Flags only, no config file and no env-var binding. `Long` and `Example` strings on every command are the primary user documentation, so keep them accurate; the README examples mirror them.
- **Errors**: stdlib `errors` and `fmt.Errorf` with `%w`. No `pkg/errors`. Return errors from `RunE`; do not `os.Exit` inside commands.
- **Logging**: none. Commands print results to stdout and rely on Cobra to print errors to stderr.
- **Passwords/PINs**: `pemutil.PromptPassword` is wired to `termutil.ReadPassword` in `root.go`; PINs can also come from the URI (`pin-value=`, `pin-source=`).
- **Build tags**: darwin-only cgo code is guarded with `//go:build darwin && cgo`. Upstream backends honor `noyubikey` / `nopkcs11` tags (used by `build-fips`). Keep cross-platform code out of `internal/darwin/`.
- **Imports**: three groups (stdlib, third-party, `go.step.sm/crypto`, then this module) as enforced by `make fmt`.
- **License headers**: Go files carry the Apache-2.0 header; `internal/termutil` keeps its original BSD header from age.
- **Releases**: pushing a `v*` tag runs `release.yml` (GitHub release, goreleaser-pro archives + deb/rpm, four Docker images). Version strings come from the tag; do not hand-edit `cmd.Version`.

## Related Repos

- `go.step.sm/crypto` (github.com/smallstep/crypto) provides every KMS implementation; most feature work starts there and this repo just exposes it. To develop against a local checkout add `replace go.step.sm/crypto => ../crypto` to `go.mod` temporarily (never commit it).
- `github.com/smallstep/cli-utils` supplies `step.Init()` / `step.Path()` for the TPM storage directory.
- `github.com/smallstep/cli` (`step`) invokes this binary for `step kms ...` and for `--kms` on `step certificate create/sign`.
