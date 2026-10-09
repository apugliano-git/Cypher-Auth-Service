# Cypher identity contract

Version: closeout of 2026-10-09. Routes and response fields are unchanged. This is a JWT contract, not OAuth2/OIDC discovery.

## Emission and own validation

- Signature: RS256 only, RSA >=2048 bits from the configured local PKCS12 alias. Startup fails for invalid keystore/configuration. No network key resolver is used.
- Header: mandatory configured `kid` (`JWT_KEY_ID`, default `cypher-key`). Compression (`zip`) is rejected before payload parsing; unknown critical headers are rejected by JJWT. `jku`/`x5u` are ignored and never determine key retrieval.
- Issuer: exact `JWT_ISSUER`, default `http://localhost:8080`. Use the same stable issuer in each demo deployment/consumer; it is an identifier, not an OIDC Authority endpoint.
- Audience: `keystone-ecosystem` (array on emission); identifies demo APIs, not delegated permission.
- Subject: required canonical UUID of the user, used as Ratchet's holderRef; never email or caller-supplied ID.
- `iat` and `exp`: required integer NumericDate seconds, iat <= now+30 s, exp > iat, lifetime <=900 s; expiration rejected at exp+30 s exactly. `nbf` is optional, integer NumericDate seconds and <=exp; parser enforces its future boundary with the same skew. Servers must synchronize clocks.
- Required `email` is a nonblank string <=255 and `role` must be exactly `USER` or `ANALYST` (case-sensitive). Emission and own validation share this same allowlist; unsupported stored roles fail before issuance. Public registration always creates `USER`, ignoring caller-supplied role/identity fields.
- JWKS: only public `kty`, `kid`, `use`, `alg`, `n`, `e`; n/e are minimal unsigned Base64urlUInt, never Java's sign-padded encoding. No private certificate/keystore material is exported.

Own `/auth/me` rejects invalid bearer credentials with 401; its DTO contains only id/email/role. No privileged role route exists to demonstrate a 403 policy. Tests cover missing/wrong claims, unsigned/altered/wrong-key/algorithm/expired/malformed tokens and independent Spring/Nimbus verification of a real HTTP token/JWKS.

## Authorized local provisioning

Keystone's plan specifies a locally provisioned `ANALYST`. This is a trusted operator action for a known synthetic account, not an HTTP capability. Create that account through registration, then use an authorized local database connection and an exact UUID:

```sql
\prompt 'Synthetic user UUID: ' user_id
BEGIN;
UPDATE users SET role = 'ANALYST'
WHERE id = :'user_id'::uuid AND role = 'USER'
RETURNING id, role;
-- Confirm exactly one expected synthetic UUID; otherwise ROLLBACK.
COMMIT;
```

The operator must authorize the target/environment; no real account is provisioned by tests or this audit. A fresh login/refresh emits the stored role. Previously issued access tokens keep their previous role until expiration+skew; a downgrade is not immediate JWT revocation. Consumers decide endpoint permissions: the shared audience alone grants no analyst access. No schema migration or administrative API is added. Both roles round-trip through JWT and HTTP login/refresh/me tests; `ADMIN`, wrong case, role prefixes/lists, null and empty roles are rejected.

## Compatibility and consumer pending work

Tokens issued before this change lack mandatory claims and must be replaced by login or refresh. Existing user IDs/password hashes/emails and persisted refresh tokens remain valid; rotation now inherits the presented token's absolute expiry. No automatic data normalization/migration occurs.

Ratchet (`../Ratchet-Payments-Engine/reservation-service/src/main/resources/application.properties` and `src/main/java/com/ratchet/reservation/config/SecurityConfig.java`): retain its fixed configured JWKS URI; add an explicit NimbusJwtDecoder constrained to RS256 and validators for exact issuer, audience, required canonical UUID subject, required temporal claims and 30-second skew. Current `jwk-set-uri` configuration alone does not establish issuer/audience validation. Preserve `HoldController`'s subject ownership checks. Test valid A/B identities, B accessing A's hold, wrong iss/aud/key/kid, missing sub/exp, expiry outside skew, and independently verify HTTP JWKS. No Ratchet files changed here.

Keystone (`docs/superpowers/plans/2026-09-07-keystone-plan-final.md`, identity section): its README remains design/planning, so plan text is not implemented integration. When an application exists, use standard .NET JWT middleware/IdentityModel with a fixed JWKS URL and bounded cached retrieval; exact issuer/audience, RS256, kid/sub/exp and 30-second skew. Do not set `Authority` to Cypher expecting discovery, and do not disable validation. Map the literal `role` claim explicitly (for example `RoleClaimType = "role"`) and require `ANALYST` only on analytics endpoints. Test USER→403 and ANALYST→success there; Cypher itself has no analytics/privileged route. Run `dotnet test` plus a real Cypher HTTP token/JWKS fixture. SDK/app absent here: **BLOCKED, not PASS**. Do not log login bodies or return/persist refresh in a Keystone V1 flow that excludes it.

A proxy must strip forged forwarding headers and permit upstream access only from explicitly trusted proxy addresses. Cypher currently ignores forwarding headers. Behind Keystone all requests share the peer IP budget; per-account limits still apply. Choose and test proxy trust/address propagation before exposure; never globally trust supplied X-Forwarded-For.

## Rotation and residual token life

Cypher publishes one active key. It has no overlapping key ring or tested zero-downtime rotation. For a planned local replacement, stop issuance, allow the old 900 s token lifetime plus 30 s skew to drain, replace the keystore with a new key and unique kid, restart, refresh consumers' trusted JWKS cache, and test new tokens. This procedure has an interruption.

After suspected compromise, stop issuance and replace the key urgently, remove the compromised public key from every consumer/cache, invalidate refresh sessions as part of the owner's incident response and force reauthentication. Waiting for an overlap is inappropriate for a compromised key. Removing a key from Cypher does not evict all consumer caches. No real key/token revocation is performed by this audit.

Refresh replay rejects only the consumed token. The successor remains usable; theft followed by the thief's first renewal is not detected. A committed refresh whose response is lost cannot be recovered by replaying the old token: clients must avoid parallel renewals and reauthenticate after ambiguous failures. Signing/storage errors before commit roll back consumption. A seven-day expiry is absolute; login can create a new session. Revoked refresh sessions leave issued access tokens valid until expiration/skew unless consumers withdraw the signing key (global effect).
