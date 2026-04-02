# Proposal: Hybrid CLI Auth UX

Decision:

- local CLI: prefer `loopback + PKCE`
- remote CLI: prefer `device flow`

Both signup and sign-in should use the same split.

## 1. Local CLI Flow

Use this when the CLI can open a browser on the same machine.

Flow:

1. CLI starts auth.
2. CLI generates:
   - `state`
   - `code_verifier`
   - `code_challenge`
   - loopback `redirect_uri`
3. CLI opens the browser.
4. User completes signup or sign-in in the browser.
5. Browser redirects to the local callback with a one-time code.
6. CLI exchanges `code + code_verifier` for the existing internal Passport JWT.

Properties:

- best UX
- no manual code entry
- browser alone cannot mint the final CLI session

## 2. Remote CLI Flow

Use this when the CLI is running over SSH, on a remote server, or anywhere loopback callback is not practical.

Flow:

1. CLI starts auth.
2. Backend creates:
   - short `user_code` for human input
   - high-entropy `device_code` for the CLI only
3. CLI prints:
   - verification URL
   - `user_code`
4. User opens the URL in a browser on any device.
5. User signs up or signs in.
6. User enters the `user_code` in the web UI.
7. Backend binds the logged-in browser user to the pending CLI session.
8. CLI polls using `device_code`.
9. Backend returns the existing internal Passport JWT once approved.

Properties:

- works across devices
- no browser callback required
- the short code is not the real credential

## 3. Security Rules

### 3.1 Local Flow

- allow only loopback redirect URIs
- require PKCE
- require exact `state` match
- callback code must be one-time and short-lived
- final token must remain the existing internal JWT backed by `auth_session`

### 3.2 Remote Flow

- `user_code` is only for human entry
- `device_code` is the real CLI credential
- `user_code` must be short-lived, rate-limited, and single-use
- CLI gets a token only after successful polling with `device_code`
- browser login alone must not mint the CLI session

## 4. Backend Changes

### 4.1 Add A Dedicated CLI Auth Session Model

Suggested file changes:

- [db.go](/Users/zfdang/workspaces/kite/passport/pkg/model/db/db.go)
- new [cli_auth.go](/Users/zfdang/workspaces/kite/passport/pkg/model/cli_auth.go)

Suggested fields:

- `id`
- `purpose` (`signup` or `login`)
- `flow` (`local_pkce` or `device`)
- `email_hint`
- `redirect_uri`
- `state_hash`
- `code_challenge`
- `code_challenge_method`
- `callback_code_hash`
- `user_code_hash`
- `device_code_hash`
- `user_id`
- `expires_at`
- `approved_at`
- `consumed_at`
- `created_at`
- `updated_at`

### 4.2 Add Service Methods

Suggested file changes:

- new [cli_auth.go](/Users/zfdang/workspaces/kite/passport/pkg/service/cli_auth.go)
- [service.go](/Users/zfdang/workspaces/kite/passport/pkg/service/service.go)

Suggested methods:

- `InitCLIAuth(ctx, req)`
- `GetCLIAuthPageData(req)`
- `ApproveCLIAuthWithBrowser(ctx, userID, req)`
- `ExchangeLocalCLIAuth(ctx, req)`
- `PollDeviceCLIAuth(ctx, req)`
- `SubmitDeviceUserCode(ctx, userID, req)`

Behavior:

- local flow:
  - store `state_hash`, `code_challenge`
  - on browser approval, mint one-time callback code
  - on exchange, verify PKCE and issue internal JWT
- device flow:
  - mint `user_code` + `device_code`
  - store hashes only
  - browser submits `user_code`
  - CLI polls with `device_code`
  - on approval, issue internal JWT

Reuse existing internal JWT issuance:

- [signup.go](/Users/zfdang/workspaces/kite/passport/pkg/service/signup.go#L303)

Do not return OAuth access tokens for CLI auth.

## 5. HTTP Routes

Suggested file changes:

- new [cli_auth.go](/Users/zfdang/workspaces/kite/passport/pkg/handler/cli_auth.go)
- [server.go](/Users/zfdang/workspaces/kite/passport/pkg/server/server.go)

Suggested routes:

- `POST /v1/cli-auth/init`
- `GET /cli-auth/authorize`
- `GET /v1/cli-auth/page-data`
- `POST /v1/cli-auth/approve`
- `POST /v1/cli-auth/local/token`
- `POST /v1/cli-auth/device/submit-code`
- `POST /v1/cli-auth/device/poll`

Route use:

- local CLI uses:
  - `init`
  - `authorize`
  - `page-data`
  - `approve`
  - `local/token`
- remote CLI uses:
  - `init`
  - `page-data`
  - `device/submit-code`
  - `device/poll`

## 6. CLI Changes

Suggested file changes:

- new `/Users/zfdang/workspaces/kite/passport-cli/internal/browserauth`
- new `/Users/zfdang/workspaces/kite/passport-cli/internal/deviceauth`
- [client.go](/Users/zfdang/workspaces/kite/passport-cli/internal/apiclient/client.go)
- [init.go](/Users/zfdang/workspaces/kite/passport-cli/cmd/signup/init.go)
- [init.go](/Users/zfdang/workspaces/kite/passport-cli/cmd/login/init.go)

Behavior:

- if local interactive browser is available, default to local PKCE flow
- if `--remote` is passed, or no local browser callback is possible, use device flow

Suggested CLI flags:

- `--remote`
- `--device`
- `--no-browser`

Local flow helper responsibilities:

- open browser
- run callback listener
- validate `state`
- exchange callback code

Device flow helper responsibilities:

- print URL and `user_code`
- poll backend with `device_code`
- stop on success, expiry, or denial

## 7. Frontend Changes

Frontend needs one browser page that can handle both:

- local PKCE approval
- remote device code entry

Required behavior:

1. load CLI auth page data
2. complete signup or sign-in
3. if flow is `local_pkce`, call approve and redirect to loopback URL
4. if flow is `device`, show code input and submit `user_code`

## 8. Migration

Keep existing endpoints during migration:

- `/v1/signup/init`
- `/v1/signup/status`
- `/v1/signup/exchange`
- `/v1/login/init`
- `/v1/login/verify`

Recommended order:

1. add shared CLI auth session model
2. implement local PKCE path
3. implement remote device path
4. switch CLI defaults:
   - local -> PKCE
   - remote -> device flow
5. deprecate manual OTP path

## 9. Tests

Backend:

- loopback redirect validation
- PKCE verifier mismatch
- callback code replay rejection
- `user_code` rate-limit and expiry
- `device_code` polling success / expiry / denial
- internal JWT issuance after both flows

CLI:

- local callback success path
- local callback state mismatch
- remote polling success path
- remote expiry path
- config write only on successful exchange

## 10. References

- [RFC 8252: OAuth 2.0 for Native Apps](https://www.rfc-editor.org/rfc/rfc8252.html)
- [RFC 7636: Proof Key for Code Exchange by OAuth Public Clients](https://www.rfc-editor.org/rfc/rfc7636.html)
- [RFC 8628: OAuth 2.0 Device Authorization Grant](https://www.rfc-editor.org/rfc/rfc8628.html)
