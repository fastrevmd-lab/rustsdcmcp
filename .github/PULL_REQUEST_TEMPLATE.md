## Summary

<!-- What does this PR do, and why? -->

## Changes

<!-- Bullet list of what changed -->

## Verification

<!-- Exact commands you ran and their result. "Should work" is not verification. -->

```sh

```

## Checklist

- [ ] `cargo fmt --all -- --check` passes
- [ ] `cargo clippy --workspace --all-targets --all-features --locked -- -D warnings` passes
- [ ] `cargo build --workspace --locked` and `cargo test --workspace --locked` pass
- [ ] Tests added or updated for this change, and they fail against the old code
- [ ] `cargo audit --deny warnings` and `cargo deny check licenses bans sources` are clean, or any new advisory/license exception is called out below
- [ ] This PR does **not** touch any device- or tenant-facing config/command path (SDC client requests, tool argument handling, change-set prepare/approve/apply), **or** it does and that's explained below, including how the deterministic prepare → approve → apply control is preserved
- [ ] Any fixtures, examples, or test data added or changed are synthetic — no real SDC tenant IDs, API tokens, hostnames, device serials, or real device/policy configuration
- [ ] No new telemetry, analytics, or outbound network call added
- [ ] If this touches a path that can act on SDC: deterministic code decides, not a model output

## Anything you're unsure about

<!-- Flag it here rather than hoping review catches it -->
