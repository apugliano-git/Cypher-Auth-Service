# Cypher security audit

Updated 2026-10-10 after review/cleanup of published commits `16b3084` and `a86967a`. Scope: Cypher only, synthetic local fixtures and loopback demo. No production certification, paid LLM calls, real credential rotation, consumer modifications or deployment.

## Baseline and scope

The audit started from clean commit `0392710105a86abf4873aaafab83076d1e42110a`. The first restricted run failed on Docker access; the elevated baseline executed **6 tests, zero failures/errors/skips**. Recorded stack: Java 21.0.3, Maven Wrapper 3.9.16, Boot 4.1.1, PostgreSQL 16 and Redis 7. Historical failures and successive regressions are retained as value-free [verification records](evidence/verification-history.json); these are summaries of the sanitized `a86967a` snapshot, not new runs. Git retains that snapshot for review.

Untrusted HTTP clients submit credentials, bearer/refresh tokens and metadata. A valid user can consume resources; a stolen-token holder can replay tokens. Password hashes, signing key, identity/role, refresh continuity and audit evidence are assets. DB/Redis/local keystore are trusted infrastructure; geolocation and optional LLM data cannot authorize a request. Email identity remains exact and case-sensitive; no automatic merging or migration.

POST register/login/refresh → request bounds/validation → controller → services → PostgreSQL/Redis. GET me → bearer validation → identity DTO. GET JWKS → local public key only. GeoIP is local; explanations are optional external HTTP. No cookie authentication or public administration API.

## Findings and disposition

Severity reflects actual prerequisites/impact. No unsigned-token bypass or public role elevation was demonstrated. Critical/high infrastructure component matches are classified separately from confirmed Cypher vulnerabilities; no owner risk acceptance is implied.

| ID | Priority / CIA | State | Root evidence / preconditions / impact | Fix and regression |
|---|---|---|---|---|
| C01 | Medium / I | FIXED | JwtService accepted same-key signed JWTs lacking required claims; parser could accept other RSA algorithms / numeric-date strings | Exact issuer/audience/kid, canonical sub, required strict dates/role/email, RS256, 30 s skew; JwtContractTest. Original acceptance and string-date regressions failed before patch |
| C02 | Medium / I,A | FIXED | JwksController encoded 2048-bit modulus as 257 bytes with Java sign padding; interoperability issue rather than private-key leak | Minimal unsigned RSA integers; independent HTTP Spring/Nimbus token verification |
| C03 | High / A | FIXED | LoginService reset IP/email counters on valid login; attacker with own account could repeat expensive valid hashing and SQL issuance without limit | Valid-login budget regression RED→GREEN; retain counts. Blocked IP now rejects before mutating another account's budget (independent review reproduction) |
| C04 | Medium / A | FIXED | RateLimitService INCR/EXPIRE gap could leave persistent keys; nullable result treated as zero | Atomic Lua, orphan-TTL repair, 32 concurrent counters, expiry/failure tests; no fail-open |
| C05 | Medium / A,I | FIXED | Duplicate registration race returned 500; User-Agent >255 broke audit SQL; login/refresh/email/body unbounded | SQLSTATE 23505 domain mapping after saveAndFlush; 5-way 201/409 race; DTO/body/header/bearer bounds, metadata truncation/control-character removal |
| C06 | Medium / I,A | FIXED | Controller signed after refresh commit, leaving consumed token on signer failure; renewal could continue indefinitely | Sign inside transaction; inherit absolute expiry; 8-way races repeated three times, exact 200/401/persistence, replay/successor, deterministic expiration, signer rollback. Login audit/issuance transaction and failure rollback |
| C07 | Medium / A,C | FIXED | LLM called without configured key, could queue/block without bound; read timeout did not bound trickling response or drain on close | Explicit opt-in+key, 2 workers/16 queue, Java HttpClient cancellation deadline 5 s, streaming 16 KiB limit, 2000-character text; local 429/500/malformed/large/slow/trickle tests, no paid calls |
| C08 | Medium historical / C; High if reused for reachable real DB | OPERATOR VERIFICATION REQUIRED | Two historical literal DB password locations remain in reachable history. Current code uses env; no current external use can be established from repository | Locations-only scan evidence. Owner must verify non-use/non-reuse and rotate if applicable; no real rotation/history rewrite. This is not an accepted risk |
| C09 | Low / I | FIXED | Non-positive anomaly travel duration fabricated a 0.001-hour interval and flagged huge speed | Unknown result for non-positive duration; RED→GREEN. Literal-only geolocation excludes hostname DNS and private/link-local/multicast addresses |
| C10 | Medium component / I,A | PATCHED; applicability qualified | OSV flagged Tomcat 11.0.24. Official advisories require Tomcat DIGEST/FORM/declarative constraints, not Cypher's Spring bearer flow; additional protocol fixes exist | Tomcat 11.0.26; full HTTP suite. Jackson 3.1.7/2.21.7 and BC 1.86 patched within current stack; final OSV Maven scan has no matches. OS/JRE/images remain separate |
| C11 | Medium / C | FIXED local default | Compose published API on all interfaces over HTTP | Bind 127.0.0.1 by default; TLS/proxy trust before any public exposure. No deployment performed |
| C12 | Low / C | HARDENED | New-password Argon2 defaults used 16 MiB vs current OWASP minimum recommendation 19 MiB/2 iterations/parallelism 1 | New hashes use 19 MiB; policy test failed before patch, legacy hashes still verify; measured campaign repeated. Existing lower-cost hashes are not automatically rehashed |
| C14 | Medium / C | FIXED | Spring default validation warning included rejected password text on overlength credentials, observed in the fresh HTTP campaign | Capture-log regression and generic 400 advice; no password/body logging permitted |
| C15 | Medium component / A,I | FIXED; zero final matches | Trivy found Alpine libpng/zlib CVEs in the built image; no PNG processing or native gzprintf caller was found on authentication paths | Targeted runtime package upgrades, independent final image rescan; not a demonstrated HTTP exploit |
| C16 | Operational / C,I,A | CLASSIFIED FOR LOCAL SCOPE; PUBLIC PREREQUISITES OPEN | Old cached DB/Redis image packages matched security advisories; many fixed by updated official images. Remaining component matches require applicability review; no confirmed auth exploit | Updated/pinned Compose digests, real fixture suite + rescan; complete advisory classification, no blanket suppression or distro migration |
| C17 | Medium / A,I | FIXED | Issuer emitted stored ANALYST while own verifier allowed only USER; invalid stored roles could also be signed | Shared exact USER/ANALYST allowlist for issuance/validation; JWT red→green and HTTP login/refresh/me plus public injection regression; no admin API |
| C18 | Medium / C | FIXED; verification complete | Raw test logs published at commit 16b3084 contained generated Boot passwords and rejected synthetic credentials; the previous pattern scan missed these formats | Sanitize 24 credential-bearing log lines, exclude unused Boot user, regression for no default user/Basic access, tested evidence guard and gated/sanitized CI output; previous Git history remains |
| C13 | Operational / A,I | REQUIRED BEFORE EXPOSURE | No automatic retention/session cap; DB superuser local default; single signing key; legacy local-zone audit timestamps; proxy/NAT shared budgets | Procedures and explicit prerequisites in operations/identity contract. No purge, admin subsystem or silent timestamp/account migration added |


## Verification and reproducibility

Run the actual suite, with Docker available for disposable fixtures:

```bash
./mvnw clean verify
python3 -m unittest discover -s scripts/security -p test_evidence.py
python3 scripts/security/evidence.py docs/security/evidence
```

Fresh cleanup verification on 2026-10-10: **52 Java tests, zero failures/errors/skips; seven Python regressions PASS; evidence privacy check PASS** ([test summaries](evidence/final-tests.log)). The fixture directory observed during this run was absent after the test JVM exited. All eight Java source files under `src/test` are active tests or the shared synthetic-key fixture; the four scripts are used by tests, CI or documented reproduction. The tests cover:

- JWT roles/mandatory claims/RS256/signature/kid/skew and malformed/oversized/compressed tokens; public registration ignores injected roles; HTTP USER/ANALYST login/refresh/me; independent Spring/Nimbus verification using served JWKS.
- Five-way duplicate registration (one 201, remaining 409); eight-way refresh races repeated three times (one 200, remaining 401), persisted hashes/revocation/lineage/absolute expiry; replay, exact expiration, signer/constraint/audit failure rollback and restart continuity.
- Atomic Redis counter/TTL/concurrency/expiry, valid-login budgets, blocked-IP isolation, forged forwarding headers, bounded bodies/headers/passwords/refresh/metadata, DB/Redis errors and recovery; disposable Redis only, never personal `flushDb()`.
- Optional LLM disabled/configured behavior, bounded queue, local stub failures/429/5xx/malformed/oversized/trickling responses and deadline cancellation; literal-only GeoIP and non-positive duration handling.
- Synthetic backup/restore, schema validation/restart and finite stepped/sustained HTTP campaigns with SQL invariants; password-log privacy and absence of the unused Boot development account/Basic access.

Regressions were observed failing before their fixes where feasible; the historical record includes those red/green results. A successful Docker package with `-DskipTests` is not suite evidence. Hosted CI remains unverified locally: `gh` lacks API authentication, while SSH Git access works.

### Measured local workload

Retained [stepped metrics](evidence/load-final.json) and [sustained metrics](evidence/sustained-final.json) are the final small campaigns, not aggregates of intermediate runs. They preserve samples, statuses, latency distributions, resource readings, configuration and recovery. Machine/tool baseline: [machine](evidence/machine.json).

The sustained campaign schedules sixty differentiated synthetic IP/account workflows over **180 seconds**, concurrency **1**, each doing register, correct login, incorrect login and refresh: **240 measured admitted requests**, followed by recovery register/login. Controls stay active: login/register 5 attempts per five-minute fixed window, refresh 30 per IP; no counter resets or diagnostic profile. This is differentiated legitimate traffic, not one shared NAT or proof of distributed-abuse resistance.

Budget: HTTP timeout 5 s, driver <210 s, sampled JVM RSS <2 GiB, host available RAM >2 GiB, stop on unexpected response; each operation/minute admitted p95 <1 s. SQL assertions require 61 users, 121 audit rows, 121 hashed refresh rows, 60 revoked predecessors, unique emails and consistent successor/revocation/absolute expiry, <=10 DB connections and successful recovery. Stepped load separately checks 226 requests including setup/recovery and active expected 429s. The JSON separates admitted 2xx/401, expected 429 and errors/timeouts. These finite results establish no maximum capacity, long-run memory stability, production SLO or DDoS guarantee.

### Dependencies and infrastructure

The final Maven/OSV scan queried 164 public coordinates and returned zero matches at its recorded date ([coordinates](evidence/dependencies-final.txt), [result](evidence/osv-final.json)); this is time/database limited. Maven Wrapper's distribution digest was verified against the official SHA-512 ([record](evidence/wrapper.json)). No new stack migration was made.

All **592 current PG/Redis vulnerability matches** remain in the [scan projection](evidence/infrastructure-scans.json), including all severities, package versions, corrections, primary URLs and vendor severity/CVSS. Unrelated SBOM inventories/repeated advisory prose and superseded raw scans were removed; previous severity counts remain. All **43 unique HIGH/CRITICAL identifiers** map to prerequisites, configured exposure, correction and proposed local/public disposition in [classification](evidence/infrastructure-classification.json); [official-source snapshots](evidence/official-infrastructure-advisories.json) support those decisions. Sources/scans were checked 2026-10-09, not refreshed by this cleanup.

PostgreSQL and Redis digests remain pinned in Compose. The configured profile and disposable same-image probes ([PG](evidence/postgres-exposure.txt), [Redis](evidence/redis-exposure.txt)) have no HTTP shell, privileged/SYS_ADMIN/host namespace/device access, homed/TPM workloads, untrusted archive ingestion, DTLS or XML SQL input. Gosu's affected embedded Go parsers are not called by its trusted UID-switch/exec flow. MiniZip is a Debian binary-package false positive. Stable vendor patch gaps remain; adding an affected parser/privilege/SQL feature requires reassessment. The classification permits only the tested synthetic local boundary; it does not accept component risks for arbitrary deployment.

The last built Cypher image had zero Alpine/JAR matches and UID 1000/JRE 21.0.12.1+1; its scan is retained in the projection. That image **predates the Boot-user exclusion** and was not rebuilt here. Native JRE internals are not exhaustively audited; no deployment/image publication is claimed.

## Publication correction and cleanup

Publishing raw audit logs at `16b3084` was an evidence-handling error. The owner-reported generic-password alert came from Spring's generated development account. The publication rescan found **13 generated Boot warnings, 10 rejected synthetic credential fields and one other assignment** ([inventory](evidence/evidence-exposure.json)). `a86967a` removed those values from the branch tip and excluded the unused default user. Basic credentials returned 401 in the reproduction; no live DB/keystore/Anthropic exposure was established by that specific report. C08 remains a separate unresolved owner check.

The evidence guard handles demonstrated credential formats; multiline cases were reproduced and fixed. CI publishes only allowed test/build summaries, preserves Maven failure, omits raw reports and gates public artifacts. This is a bounded format guard, not comprehensive secret detection. See [publication procedure](operations.md#publishing-sanitized-evidence).

The cleanup removes empty/intermediate/duplicate evidence, the obsolete uncommitted-tree manifest, four unused imports and one duplicate import. Active security tests, load scripts and fixture helpers stay. A real isolated JVM probe reproduced the fixture directory leak: `deleteOnExit` runs in reverse registration order. Registering the parent before its file removes both at exit ([probe](evidence/temporary-fixture-cleanup.json)). Existing unrelated files/volumes/secrets are untouched.

Old commits and possible previous CI logs/artifacts remain accessible; branch cleanup does not erase them or close alerts. No history rewrite, force push, real rotation or alert dismissal took place. [Historical credential locations](evidence/historical-credentials.json) still require the owner’s non-secret confirmation and applicable rotation in [operations](operations.md#historical-credential-verification--owner-action).

## Checkpoints and verdict

| CP | Local-scope status | Evidence / boundary |
|---|---|---|
| CP0 | PASS | Actual six-test baseline in verification history; synthetic fixtures |
| CP1 | PASS | HTTP/trust boundaries, prioritized findings and minimal compatibility plan |
| CP2 | PASS | JWT/roles/public registration/JWKS adversaries and independent Java verifier; actual consumers pending |
| CP3 | PASS | Real PostgreSQL registration/refresh races, persistence, replay/expiry/rollback |
| CP4 | PASS | Active limits, bounded/degraded dependencies, LLM stubs and admitted sustained work |
| CP5 | PASS local | Actual final suite/campaign, restore/restart, scans/classification; hosted CI/public runtime not claimed |
| CP6 | PASS synthetic local stage | Own fixes traced; C08 owner verification and public/consumer prerequisites remain open |

**Verdict:** suitable for a finite isolated synthetic local demo within the measured budget. Historical/real credentials remain **BLOCKED on owner verification**; no favorable public/production or complete ecosystem integration claim. Next consumer work is Ratchet/.NET/Keystone validation as specified in the [identity contract](identity-contract.md). Public TLS/proxy trust, restricted DB role, retention/storage, key distribution/rotation and current patched runtime still require implementation/owner decisions.

### Supporting standards and official sources (consulted 2026-10-08)

[OWASP ASVS 5.0.0](https://github.com/OWASP/ASVS/blob/master/5.0/docs_en/OWASP_Application_Security_Verification_Standard_5.0.0_en.json): V6.1.1/V6.3.1 rate-control documentation/enforcement, V6.2.8 exact password verification, V6.2.9 long passwords; V6.3.8 enumeration is not fully satisfied because registration intentionally returns 409 and timing equality is not proved. This is supporting guidance, not ASVS certification or full level compliance.

[OWASP API Security 2023](https://api-security.owasp.org/editions/2023/en/0x00-header/): API2 authentication, API4 bounded resources, API8 deployment configuration, API10 optional upstream data. [OWASP password storage](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html) supports the selected 19 MiB Argon2id baseline, not a hardware-independent security guarantee.

[Redis INCR](https://redis.io/docs/latest/commands/incr/) documents the combined-counter TTL race and Lua remedy. [RFC 7518](https://www.rfc-editor.org/rfc/rfc7518.html) defines unsigned RSA encoding. [JJWT upstream](https://github.com/jwtk/jjwt) documents parsing; effective 0.12.5 behavior is verified by tests, not assumed from latest examples.

[Apache Tomcat official advisories](https://tomcat.apache.org/security-11.html): OSV matches CVE-2026-65905, CVE-2026-65182, CVE-2026-68525 require configurations absent here; patch 11.0.26 also includes later protocol fixes. [Spring CVE-2026-47877](https://spring.io/security/cve-2026-47877/) concerns an OAuth authorization-server consent page absent in Cypher, and effective Security 7.1.1 is patched. [Jackson advisory](https://github.com/FasterXML/jackson-databind/security/advisories/GHSA-wv8q-qhhj-9h54) requires polymorphic fallback not enabled in these DTOs; patched BOMs nevertheless remove old component matches. [BC releases](https://www.bouncycastle.org/download/bouncy-castle-java/) provide 1.86; [CVE-2025-8885](https://github.com/bcgit/bc-java/wiki/CVE%E2%80%902025%E2%80%908885) was already fixed before 1.78.1 and concerns untrusted ASN.1, not this password path. No CVE is inferred from age alone.

Evidence: [final dependency tree](evidence/dependencies-final.txt) and [final OSV scan](evidence/osv-final.json): 164 Maven artifacts queried, zero final matches. OSV is a secondary index, not complete advisory coverage; official sources/applicability take precedence. The retained infrastructure projection records image results separately. Maven Wrapper distribution SHA-512 matched official Maven Central and SHA-256 is pinned ([evidence](evidence/wrapper.json)); cached installations are not revalidated on every invocation.

## Tested scope and remaining checks

JWT adversaries are bounded deterministic cases plus a small malformed HTTP campaign, not exhaustive fuzzing. Unit tests cover numeric types, exact expiration/skew, missing/wrong claims, unsigned/altered/other-key/algorithm, compressed/duplicate headers, large inputs, URLs not controlling trust, invalid keystore config. There is no demonstrated role-protected 403 route (N/A); no browser UI/cookies/CORS added. Access ownership is the signed UUID, and HTTP me fields are constrained.

Real PostgreSQL/Redis tests cover registration/login/me/JWKS/refresh, hash-only rotation state, three 8-way refresh races, 5-way duplicate registration, signer/login-audit rollback, Redis pause/recovery and PostgreSQL exclusive-lock timeout/recovery. This does not prove every failure mode (e.g. a network partition mid-commit), process-crash durability or unlimited availability. Refresh replay only rejects old credentials; loss after commit requires reauthentication. Account budgets across multiple admitted IPs remain an abuse/availability trade-off.

Optional LLM is tested solely with local controlled responses, including actual drip cancellation; no Anthropic call or spend. GeoIP tests use missing/corrupt data and mocked coordinates; licensed MaxMind accuracy/live coverage is not validated. Audit data and LLM text remain sensitive/untrusted; timestamp-zone limitations and retention are operator decisions. No notification/MFA/theft-detection completeness is claimed.

Independent Java Spring/Nimbus validates real HTTP tokens/JWKS and rejects foreign issuer/audience. Full Ratchet ownership/integration and .NET/Keystone remain **BLOCKED/outside consumer implementation scope**; SDK absent, Keystone is a plan. Exact pending files/tests are in [identity contract](identity-contract.md). Nexa was not audited or used.

## Source and regression locations

The final commit and retained verification records identify the reviewed source. Historical reproducers are summarized in verification history; private `.env` and real keystores are excluded.

| Findings | Source / regression location |
|---|---|
| C01 | `src/main/java/com/augustopugliano/cypher/service/JwtService.java:95`; corresponding named tests in `src/test/java/com/augustopugliano/cypher/` |
| C02 | `src/main/java/com/augustopugliano/cypher/controller/JwksController.java:28`; corresponding named tests in `src/test/java/com/augustopugliano/cypher/` |
| C03 | `src/main/java/com/augustopugliano/cypher/service/LoginService.java:60`; corresponding named tests in `src/test/java/com/augustopugliano/cypher/` |
| C04 | `src/main/java/com/augustopugliano/cypher/service/RateLimitService.java:22`; corresponding named tests in `src/test/java/com/augustopugliano/cypher/` |
| C05 | `src/main/java/com/augustopugliano/cypher/service/UserService.java:31`; corresponding named tests in `src/test/java/com/augustopugliano/cypher/` |
| C05 | `src/main/java/com/augustopugliano/cypher/config/RequestBoundsFilter.java:14`; corresponding named tests in `src/test/java/com/augustopugliano/cypher/` |
| C06 | `src/main/java/com/augustopugliano/cypher/service/RefreshTokenService.java:69`; corresponding named tests in `src/test/java/com/augustopugliano/cypher/` |
| C07 | `src/main/java/com/augustopugliano/cypher/service/LlmExplanationService.java:30`; corresponding named tests in `src/test/java/com/augustopugliano/cypher/` |
| C09 | `src/main/java/com/augustopugliano/cypher/service/AnomalyDetectionService.java:58`; corresponding named tests in `src/test/java/com/augustopugliano/cypher/` |
| C12 | `src/main/java/com/augustopugliano/cypher/config/SecurityConfig.java:26`; corresponding named tests in `src/test/java/com/augustopugliano/cypher/` |
