# Local operation and exposure prerequisites

This procedure is for a controlled synthetic demo. No personal volumes or actual keys were deleted/rotated by the audit.

## Boundaries and failure policy

Default Compose binds API/PostgreSQL to loopback; Redis is not published. App UID is explicit and the keystore mount is read-only. The build context allowlist excludes `.env`, `secrets`, `.git`, agent/account files and host artifacts. Compose PostgreSQL/Redis digests are pinned to the reviewed update; application base images remain mutable tags. Reproduce a release by recording/pinning their digests and scanning the actual image/JRE, not just Maven coordinates. The workstation JDK used for tests is Temurin 21.0.3; it is not a current patched deployment runtime.

HTTP POST body 16 KiB, headers 8 KiB, bearer 4096 characters, login password 128, email 255, refresh exactly 43 Base64url characters, audit User-Agent 255 (control characters replaced). Body collection has a five-second deadline checked between reads plus the connector's five-second blocking read timeout. A reverse proxy must also impose an absolute header/request deadline and connection/request limits; the direct socket configuration is not proof against slow-header or distributed DoS.

Tomcat: 16 workers, 64 connections, backlog 32. Hikari: 8 connections, 2 s acquisition, PostgreSQL connect 2 s/socket 5 s, statement 3 s/lock 2 s. Redis connect/read 1 s. These bound tested dependency failures; an unavailable DB necessarily prevents issuance/refresh/registration. `/auth/me` verifies already-issued JWTs locally. JWKS requires only the in-memory key. No fail-open bypass or retries that multiply credential/rotation requests.

Argon2 reserves 19 MiB per active hash; 16 workers could therefore need about 304 MiB just for hashing, plus JVM/application/pools. Use container CPU/memory limits suited to the measured machine and rerun the campaign. This audit does not establish a thousands-of-users target. Rate windows permit short boundary bursts; account budgets can still be exhausted from multiple admitted IPs, and NAT users share IP budgets. Those are availability trade-offs, not total brute-force prevention.

## Persistence, schema and backups

`schema.sql` and `ddl-auto=validate` are preserved. Entity explanation length now matches the existing VARCHAR(2000); no SQL alteration is required. Do not use `CREATE TABLE IF NOT EXISTS` as a migration strategy for later column changes. Back up, supply a versioned alteration, test against a restored copy, then validate. Never delete the existing volume to satisfy validation.

Audit timestamps are TIMESTAMP WITHOUT TIME ZONE in the original schema. Compose forces the JVM to UTC; use UTC for every writer. Existing rows written in another server zone retain their original meaning; conversion would require knowing that zone and a reviewed migration, not an assumed offset. Simultaneous logins/GeoIP inaccuracies do not prove intrusion; impossible-travel evaluation is advisory and can miss concurrent travel or generate false positives.

The synthetic integration check runs `pg_dump -Fc`, restores into a separate fixture database, verifies data, and reruns schema initialization without losing users. It does not establish off-site storage encryption, backup key custody or recovery of a real deployment.

For an owned deployment, keep backups encrypted and access-restricted, outside the image/source/build context. Example commands (operator supplies a least-privilege connection and secure destination):

```bash
umask 077
pg_dump "$CYPHER_BACKUP_URL" -Fc -f /secure/path/cypher.dump
createdb "$CYPHER_RESTORE_URL"
pg_restore --exit-on-error --dbname="$CYPHER_RESTORE_URL" /secure/path/cypher.dump
```

Use a fresh restore database and test login/JWKS/refresh with retained trusted keys; never restore over a personal database as a test. Preserve/restrict the keystore independently: DB restore alone cannot reproduce signatures. Avoid passwords in URLs/process arguments; use PostgreSQL's secure service/passfile mechanism in actual operation.

## Retention and session growth

There is no automatic destructive purge or session-management API. Login creates sessions; fixed limits bound per-source work, not lifetime/global database growth. Monitor database/audit size and free disk. Before public operation, the owner must set retention and incident-evidence policy; a reasonable demo proposal is 30 days of audit plus expired/revoked rotation records retained for at least the incident window. This is a proposal, not an accepted risk or active job.

Preview candidates read-only before any archival/purge:

```sql
SELECT count(*) FROM login_audit_log WHERE created_at < CURRENT_TIMESTAMP AT TIME ZONE 'UTC' - INTERVAL '30 days';
SELECT count(*) FROM refresh_tokens WHERE expires_at < CURRENT_TIMESTAMP - INTERVAL '30 days';
```

Archive with access controls first, preserve complete rotation chains needed by open investigations, then implement reviewed bounded batches with supporting expiry/time indexes. No purge was executed against real data. A disk-full DB fails issuance; it does not grant access. For a finite local campaign fixtures are discarded only by their owning Testcontainers run.

## Keys and historical credentials

See [identity contract](identity-contract.md) for planned versus compromised-key replacement. One active key is implemented; zero-downtime overlapping rotation is not. Keystore alias is separate from published key-id, so each replacement needs a unique kid and consumer verification. Permissions must restrict both the keystore and `.env` to the service owner. Never copy a private key into tests/docs or publish dumps with tokens/hashes.

Historical literal password configuration exists at commits `d2242f052f58e0a62527dfd9d03748f7ebf2090c` and `e4e635bcddd9cac90358491958bde936cf542c62`, `src/main/resources/application.properties:4`. Values are withheld. Current source uses environment placeholders; history was not rewritten. The operator must confirm that historical values are no longer used/reused anywhere and rotate if they are. This audit cannot prove external revocation. Scan output: [locations](evidence/historical-credentials.json), [reachable blob scan](evidence/secret-scan.json). Pattern scanning is not exhaustive credential detection.

## Before any public exposure

- Configure TLS at a bounded reverse proxy; prevent direct upstream access, set trusted proxies explicitly, test forged forwarding headers and shared-IP behavior. Do not open CORS or use bearer cookies without a new transport/security design.
- Use a restricted application DB role instead of Compose's PostgreSQL superuser; schema provisioning should be a separate role. Set resource/storage quotas and health/readiness behavior; protect Redis and DB networks/backups.
- Use a supported patched JDK/JRE; pin/scan actual container digests, authenticate JWKS transport, manage key distribution/caches, and confirm historical credential revocation.
- Decide retention, session/revocation policy and incident response; consider account-budget denial and optional geolocation/LLM privacy/consent. Restrict the demo to synthetic identities until these decisions and consumer tests are complete.
- Complete Ratchet/Keystone issuer/audience/subject/skew enforcement and .NET interoperability. Independent Java contract verification here is not full application integration.

## Reproduction

```bash
./mvnw clean verify
./mvnw dependency:tree -DoutputFile=target/dependencies.txt
python3 scripts/security/dependency_scan.py target/dependencies.txt target/osv.json
```

Tests require Docker and Mockito instrumentation outside a restrictive sandbox; their containers are disposable and have no personal volume mounts. CI workflow is included, but no push/hosted run occurs in this audit. Maven/OSV results are complemented by Trivy 0.75.0 scans in the audit. Re-run `trivy image --scanners vuln cypher-security-audit:20261009-closeout` on the actually built image and review official advisories/applicability.

The final Cypher image has zero Trivy Alpine/JAR matches at the recorded date. PostgreSQL/Redis cached images had many component matches; read the audit for official-source false-positive/reachability analysis and updated-image results. Binary JRE internals are not exhaustively audited by a JAR/package scan. Do not expose a deployment merely because its application image is clean.

## Historical credential verification — owner action

C08 remains **BLOCKED** until the owner supplies a confirmation or evidence of revocation/non-use; no value or password hash is required. Relevant historical locations are the two commits and line already listed above. Locally compare them privately; never paste values into the chat, tickets, command line or new commits.

Review only systems where those values could have been configured/reused:

1. Cypher's PostgreSQL endpoints/roles used since those commits: local Compose `.env` (`DB_PASSWORD`/`POSTGRES_PASSWORD`), actual persisted PostgreSQL roles, standalone installs, IDE run configurations, service/container environment files and any owned remote demo/database previously used. Include `spring.datasource.password` or overriding `SPRING_DATASOURCE_PASSWORD` settings. Inventory host/environment and role names without values. Changing `POSTGRES_PASSWORD` alone **does not update an existing database volume's role password**.
2. Cypher's GitHub Actions/repository/environment secrets and deployment-secret stores, if they were ever configured. There was no workflow at the baseline; that does not prove no manual secret or remote deployment existed. Review old configuration copies/backups and access to them; preserve incident evidence without distributing passwords.
3. Reuse: any Redis ACL/requirepass configuration, keystore protection (`KEYSTORE_PASSWORD`), another database/service or account using the same literal. Review Ratchet/Keystone secret configuration yourself **only if reused/shared**, not their implementation; do not bring Nexa into this audit. An Anthropic API key is a separate credential; do not rotate unrelated keys merely because a DB password was in Git.

Required non-secret confirmation: **which environments/roles/config stores were checked; whether the historical credentials were never used outside discarded fixtures, or were used and revoked; whether reuse exists; date of revocation/non-use review**. If used/reused, report only affected service types and completed actions. A memory-based guess or deleting the last source occurrence is insufficient. If unconfirmed, keep C08 blocked for existing/real-credential deployments; fresh generated synthetic fixtures are independent of it.

### If rotation is required (prepared; not executed)

- Restrict the affected service/network and schedule a maintenance window. Record affected environments/roles and protect an encrypted backup before changes. Do not delete/reinitialize the volume or rewrite Git history as a substitute for revocation.
- For PostgreSQL, connect using a separate trusted administrator/session and use interactive psql `\password <affected_role>` with a newly generated unique password. Use a secure terminal, not SQL text containing a password, shell arguments or pasted chat. Prefer a restricted application role for future public deployment; changing roles/grants needs a separate tested migration, not an improvised privilege cut during this rotation.
- Update the owner's protected `.env`/secret stores/IDE or service configurations consistently. Restart/recreate **only** affected application processes so Hikari opens connections with the new credential; PostgreSQL keeps its existing data volume. If necessary after owner authorization, terminate other sessions for the compromised role: password changes do not end already-authenticated connections. Never indiscriminately terminate personal sessions.
- Verify a fresh connection with the new secret, one controlled rejection using the old secret, then register/login/me/JWKS/refresh on synthetic identities. Do not log the attempted passwords. Confirm consumer/application connection recovery and record date/environment/result. If failure requires recovery, issue another new secret; do not restore a compromised one.
- Rotate every reused service credential through that service's supported owner procedure. For keystore-password reuse, replace protection and update config; if private-key material may have been obtained, follow urgent signing-key replacement in the identity contract. Password-only DB rotation does not inherently invalidate access JWTs or refresh rows. A demonstrated database compromise additionally requires incident review of users/roles/audits/session integrity; this audit cannot infer that it occurred.

Impact: issuance/registration/refresh may return 503 while DB credentials are mismatched; already-open connections can persist until restarted. Existing JWT verification/JWKS normally remains available in a running instance because the signing key is independent. Reused signing-key compromise has a different, global token/cache impact. Record the owner's final confirmation here without secrets; until then there is no favorable public-exposure claim.
