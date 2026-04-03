# Kitepass CLI Development

This document collects development-only workflows that do not belong in the public README.

## Local Build

```bash
cargo build --workspace
```

Run the CLI from source:

```bash
cargo run -p kitepass-cli -- --help
cargo run -p kitepass-cli -- --version
```

## Formatting And Linting

```bash
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
```

## Test Suite

```bash
cargo test --workspace
```

If you want to focus on the binary crate only:

```bash
cargo test -p kitepass-cli
```

## Linux Validation

For Linux or x86_64 validation, sync the repo to `nova` and build there:

```bash
~/.codex/skills/nova-linux-remote/scripts/nova-sync-repo.sh \
  --source /Users/zfdang/workspaces/agent-passport-design/agent-passport-cli \
  --dest /home/ubuntu/codex/agent-passport-cli

~/.codex/skills/nova-linux-remote/scripts/nova-exec.sh \
  --cwd /home/ubuntu/codex/agent-passport-cli -- \
  cargo build --workspace
```

## Notes

- the default public endpoint is `https://api.kitepass.xyz`
- local owner and agent state lives under `~/.kitepass/`
- `kitepass --version` includes the Cargo package version plus the current git revision when available
