# Cypher Auth Service

Cypher is a Java 21 / Spring Boot 4.1.1 authentication service for a controlled local engineering demo. It registers users, verifies passwords with Argon2id, issues RS256 access tokens, publishes a public JWKS and rotates single-use refresh tokens in PostgreSQL.

It does **not** implement a complete OAuth2/OIDC authorization server: there is no discovery document, authorization-code flow, consent or delegated scopes. JWT/JWKS interoperability does not establish those capabilities. It has not been certified for production or distributed DDoS resistance.

See the [security audit and measured scope](docs/security/audit.md), [identity contract](docs/security/identity-contract.md) and [operating procedure](docs/security/operations.md).

## Stack and behavior

Java 21, Maven Wrapper 3.9.16, Spring MVC/Security/Data JPA, PostgreSQL 16, Redis 7, JJWT 0.12.5, Bouncy Castle 1.86; test consumers use Spring Security/Nimbus. The POM is authoritative. Tomcat and Jackson patch overrides are explained in the audit.

- Registration accepts validated emails up to 255 characters and passwords of 12–128 Java characters. Login accepts existing passwords of 1–128 characters. Passwords are never trimmed or normalized. Email identity is exact and case-sensitive; no accounts are merged.
- Argon2id uses 19 MiB memory, two iterations, parallelism one, 16-byte salt and 32-byte hash. Missing accounts also perform one dummy comparison; this mitigates a large timing difference without proving indistinguishability.
- Redis implements an **atomic fixed window from the first attempt**, not a sliding window. Login allows five attempts per IP and exact email in five minutes; registration five per IP; refresh 30 per IP. Successful login does not reset the budget. Shared NAT/proxy clients share an IP budget. A window boundary can allow twice the budget over a short interval.
- Access tokens last 900 seconds. Refresh sessions have a seven-day absolute expiry; successors inherit the original expiry. PostgreSQL locks enforce single consumption. Replay rejects the old token; it does not revoke the successor/family or prove theft detection. There is no logout/admin/session cap endpoint. Revoking refresh does not revoke existing access tokens.
- Audit success means token issuance/persistence committed, not delivery acknowledged by a client. Admitted failed logins are recorded. 429 requests are represented by rate counters, not per-request SQL audit rows; refresh history is the persisted rotation chain.
- Impossible-travel detection is advisory: anomalies do not block login or enable MFA. Missing/corrupt GeoIP data or non-positive travel duration means unknown. Audit time uses the server's local zone; run in UTC consistently and preserve the original zone for legacy records.
- Anthropic explanations are off by default, and also off without a key. Enabling them sends only countries and coarse travel estimates, never credentials/tokens/IP/email. Two workers, a queue of 16, a two-second connect timeout, a five-second cancellable request deadline and response limits bound optional work. Queue saturation drops explanations without failing authentication. LLM text is untrusted and must be escaped by a UI.
- Authentication uses bearer headers and stateless security; no authentication cookies or open CORS are configured. Token responses use `Cache-Control: no-store`. Invalid protected requests return 401. Dependency failures return 503 and never silently disable limits.

## API

| Method and route | Input / output | Expected statuses |
|---|---|---|
| POST `/auth/register` | `{ "email": "user@example.com", "password": "SyntheticPassword123!" }` | 201, 400, 409 duplicate, 429, 503 |
| POST `/auth/login` | Same fields; returns `access_token`, `refresh_token`, `expires_in` | 200, 400, 401 credentials, 429, 503 |
| POST `/auth/refresh` | `{ "refresh_token": "<43-character Base64url token>" }`; returns same token fields | 200, 400 format, 401 invalid/replayed/expired, 429, 503 |
| GET `/auth/me` | Bearer token; returns only `id`, `email`, `role` | 200, 401 |
| GET `/.well-known/jwks.json` | Active public RSA key | 200 |

Registration intentionally exposes an exact-email conflict via 409. Login failures do not distinguish missing accounts from incorrect passwords in their status/body. JWT roles are exactly `USER`/`ANALYST`; registration always creates `USER`, with analyst provision described in the identity contract. No granular role-protected endpoint exists, so a positive/negative role authorization (403) contract is not claimed.

POST bodies are capped at 16 KiB, including chunked bodies. Headers are capped at 8 KiB and bearer tokens at 4096 characters. Invalid payloads are rejected before Argon2/DB work. Header/address information from `Forwarded` or `X-Forwarded-For` is ignored; only the socket peer is counted. A trusted proxy deployment requires explicit separate configuration and verification (see contract).

## Local setup

Requires Java 21, Python 3 for the bounded test campaign, Docker and Compose. Fixtures generate their own keys and ephemeral databases; they do not use personal infrastructure.

1. Copy `.env.example` to `.env`, choose unique `DB_PASSWORD` and `KEYSTORE_PASSWORD`, leave `ANTHROPIC_ENABLED=false` and `ANTHROPIC_API_KEY` empty.
2. Create a development keystore. The password entered at the prompt must match `.env`; never reuse a personal key:

```bash
umask 077
mkdir -p secrets
chmod 700 secrets
keytool -genkeypair -alias cypher-key -keyalg RSA -keysize 3072 \
  -storetype PKCS12 -keystore secrets/cypher-keystore.p12 \
  -dname "CN=Cypher Development" -validity 365
chmod 600 .env secrets/cypher-keystore.p12
```

3. Optionally obtain a licensed GeoLite2 City database and place it in `secrets/GeoLite2-City.mmdb`. Its absence disables geolocation, not authentication.
4. Run `APP_UID=$(id -u) docker compose up -d --build`. API binds **127.0.0.1:8080**, PostgreSQL **127.0.0.1:5433**; Redis is internal. The app runs with that UID and reads secrets from a read-only mount. Docker builds exclude local secrets and use the Maven Wrapper. Image tags remain mutable; image scanning/digest pinning are deployment prerequisites.
5. `curl http://127.0.0.1:8080/.well-known/jwks.json` verifies HTTP/key publication, not all dependency health.

Do not delete an existing PostgreSQL volume to upgrade. This remediation requires no schema alteration; `ddl-auto=validate` remains active. Read the operating procedure for retention, backups, key replacement and exposure prerequisites. Compose's database superuser is a local-demo default, not a least-privilege public deployment.

## Verification

```bash
./mvnw clean verify
```

This runs deterministic JWT/validation/optional-work checks, actual HTTP/PostgreSQL/Redis flows, races, failure recovery, independent Java verification, synthetic backup/restore and a short bounded load campaign with security limits active. Docker socket access and local Mockito instrumentation are required. Reports are generated afresh in `target/surefire-reports/` and `target/security-load.json`. CI runs the same command; no hosted CI execution is claimed until pushed by the owner.

To repeat only the local campaign:

```bash
./mvnw -Dtest=AuthIntegrationTest#boundedLoadPreservesDatabaseInvariantsAndRecovers test
```

Never point this campaign at public/personal services. The suite also runs three minutes of admitted traffic at concurrency one (60 synthetic source/account workflows; 240 measured requests) with limits active, resource/latency budgets and recovery assertions. The JUnit fixture creates its target and Redis cleanup is limited to its own ephemeral container. Ratchet's preauthenticated load test is not a Cypher authentication benchmark. .NET and full consumer integration are separate pending checks.

## License / author

[MIT](LICENSE). Augusto Pugliano — [GitHub](https://github.com/apugliano-git).
