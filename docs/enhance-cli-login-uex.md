# CLI Login UX Notes

> **Status**: Superseded proposal
>
> This file previously proposed a split local `loopback + PKCE` flow plus a
> separate remote device flow. The current `kitepass-cli` implementation does
> **not** use that split design.

## Current Implementation

As of 2026-04-03, the CLI uses a single owner-login model:

1. `kitepass login` requests a device code from Passport Gateway
2. the CLI generates a PKCE verifier / challenge pair
3. the CLI opens the browser when possible, but can also work when the browser
   is on another device
4. the owner signs in with passkey / WebAuthn in the browser
5. the owner approves the pending device login
6. the CLI polls the device-code endpoint with the PKCE verifier
7. Gateway returns an owner access token
8. the CLI stores that token encrypted in `~/.kitepass/config.toml`

## Why This Proposal Is Superseded

The older proposal assumed:

- a dedicated loopback callback flow for local interactive usage
- a separate remote-only device flow
- an earlier Passport auth model and terminology

The current multi-repository implementation has instead standardized on:

- device-code flow for both local and remote usage
- PKCE binding on the polling side
- owner access-token storage under `~/.kitepass/`
- browser passkey approval through the current Gateway / Console deployment

## If A Future UX Refresh Happens

If the project later adds a loopback callback flow for local interactive
ergonomics, that work should be treated as a new design effort. It should not
be assumed to reflect the current behavior of `kitepass-cli`.
