# Changelog

## Unreleased

- Add the Rust workspace and Security Director Cloud MCP binary.
- Add bounded device, policy, shared-object, and asynchronous-job read tools.
- Add preview-bound two-person policy deployment through `mecmcp-changeset`.
- Add shared `mecmcp` auth, audit, server, transport, runtime, and TLS
  composition.
- Add fixture tests, configuration example, operations guide, and security
  policy.
- Add Rust 1.97/MSRV 1.88, packaging, and security CI gates for the lab-only
  package.
- Document the lab artifact workflow, loopback-only listener, token ownership,
  journald forwarding exception, and the public-release compatibility blocker.
- Bind each lab package, checksum, and CI upload to its exact full source
  commit directory; require a Cargo-derived CycloneDX SBOM.
- Fail closed for staged live-installer tests and harden commit artifact output
  directories, SBOM metadata, and upload allowlists.
