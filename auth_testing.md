# Auth Testing Playbook — Google Sign-In on Governance Workbench

This app uses Emergent-managed Google Auth. When a Google-authenticated user
lands back on the SPA with `#session_id=<id>` in the URL fragment, the SPA
POSTs to `POST /api/v1/auth/google/session` with header `X-Session-ID: <id>`.
The backend calls
`GET https://demobackend.emergentagent.com/auth/v1/env/oauth/session-data`
with the same header, gets `{id, email, name, picture, session_token}`, then
persists a row in `governance_google_sessions` (Postgres, not Mongo — this app
does not use Mongo), sets an httpOnly cookie `governance_session` with the
`session_token`, and returns a governance JWT bound to role `governance-admin`.

## Test flow (browser)
1. Visit `<preview_url>/#/login`.
2. Click **Sign in with Google** button (`data-testid="login-google-btn"`).
   The browser goes to `https://auth.emergentagent.com/?redirect=<encoded>`.
3. Complete Google flow.
4. Redirected back to `<preview_url>/#/dashboard#session_id=<id>`.
5. SPA silently POSTs to `/api/v1/auth/google/session` with the id, receives:
   - `{accessToken, role="governance-admin", scopes=[...], clientId="google:<email>"}`
   - httpOnly cookie `governance_session=<session_token>; Max-Age=604800; Path=/; Secure; SameSite=None`
6. SPA clears the fragment, stores the token in sessionStorage (same shape as
   the client-credentials flow), toasts "Signed in as governance-admin",
   navigates to `#/dashboard`.

## Test flow (backend curl — no real Google)

You cannot mock `demobackend.emergentagent.com` from tests without egress.
For automated backend testing, we accept a **testing-only** shortcut:
if `GOOGLE_AUTH_TEST_SESSION_ID` and `GOOGLE_AUTH_TEST_SESSION_TOKEN` are set
in `/app/backend/.env`, the backend treats requests with
`X-Session-ID: $GOOGLE_AUTH_TEST_SESSION_ID` as pre-authenticated and returns
the fixture user `test.user@governance.local` without contacting
`demobackend.emergentagent.com`. This is guarded so it cannot be enabled in
production (fails if `NODE_ENV=production`).

## Endpoints
- `POST /api/v1/auth/google/session` — header `X-Session-ID: <id>` → issues
  governance JWT + sets `governance_session` cookie. Body: `{}` (empty).
- `GET  /api/v1/auth/me` — reads `governance_session` cookie OR
  `Authorization: Bearer <session_token>` and returns
  `{userId, email, name, picture, role, scopes, expiresAt}`. 401 if invalid.
- `POST /api/v1/auth/logout` — deletes DB session, clears cookie.

## Test identities to store in test_credentials.md
- Test Google account: `test.user@governance.local` → role `governance-admin`

## Success indicators
- `POST /api/v1/auth/google/session` → 200 + `accessToken` field
- Cookie `governance_session` set with `HttpOnly; Secure; SameSite=None`
- `GET /api/v1/auth/me` → 200 with fixture user data
- `POST /api/v1/auth/logout` → 204 + cookie cleared
- On the SPA, sidebar shows `governance-admin` and `@google:test.user@governance.local`
