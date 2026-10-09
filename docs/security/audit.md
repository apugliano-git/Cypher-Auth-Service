# Cypher security audit — 2026-10-08 / closure 2026-10-09

Scope: Cypher only; Keystone/Ratchet read for identity contract. No deployment, paid API calls, real-key rotation or personal data changes. Starting commit `0392710105a86abf4873aaafab83076d1e42110a`, clean main; working branch `codex/security-audit-2026-10-08`.

Current disposition is in [Bounded closeout](#bounded-closeout--2026-10-09). Earlier checkpoint results below are retained as dated evidence, not the current verdict. C08 still requires the owner’s non-secret confirmation.

## Baseline
`./mvnw test`: sandbox Docker socket denied (1 validation pass, integration environment error). Rerun outside sandbox: **6 tests, 0 failures/errors/skips**, 25.852 s. Evidence: [baseline](evidence/baseline.log). Java Temurin 21.0.3, Maven Wrapper 3.9.16, Boot 4.1.1, Testcontainers effective 2.0.5 (mixed declarations to align), Tomcat 11.0.24. Machine: 8 logical CPUs, 15,646 MiB RAM, ~8,234 MiB available, swap already in use. No applicable AGENTS.md in Cypher. Fixtures generate their own RSA key.

## Threat model / surface
Untrusted HTTP clients can submit credentials, bearer/refresh tokens and metadata; a stolen token holder can replay tokens; a valid user can consume resources. DB/Redis and local keystore are trusted infrastructure; GeoIP and LLM output are optional/untrusted data. Assets: passwords/hashes, RSA private key, session continuity, identity/role, audit evidence and bounded resources.

POST register/login/refresh → validation/filter → controller → services → PostgreSQL/Redis. GET me → bearer verification → DTO. GET JWKS → public local key only. GeoIP is local; LLM is optional outgoing HTTP. No cookie authentication intended. Account identity remains exact case-sensitive email (no migration/merging).

## Implementation plan (authorized inline execution)
1. JWT/JWKS: JwtService, JwksController, SecurityConfig/filter, properties; mandatory iss/aud/kid/UUID sub/iat/exp/email and USER/ANALYST role, RS256 only, 30 s skew, bounded tokens; unsigned RSA integers. Unit adversarial tests and independent HTTP verifier. Old tokens without new claims require login again.
2. Bound inputs and dependencies: DTOs, request filter, Redis Lua atomic counter+TTL, distinct IP/account keys, retain counters on successful login, refresh throttle; 503 on infrastructure errors, bounded pools/timeouts. HTTP/unit/real Redis regression.
3. Transactions: UserService unique-race domain error; refresh signs inside transaction, no second branch, absolute seven-day session inherited by successors. Real DB N-way races, rollback, replay and persistence tests. Replay rejects old token only; no claim of family theft detection.
4. Optional explanation: bounded executor/queue, reject/drop explanation without failing login, disabled without explicit configuration, local stub tests/timeouts/response cap. GeoIP literal addresses only; audit metadata bounded and issuance outcome coherent.
5. Operations: schema consistency/restart/backup restore synthetic tests; repository/history secret scan (redacted), dependency advisories, CI, local measured stepped load with limits active, README and identity contract.

Each fix gets a failing reproduction where feasible, targeted green regression and full suite. No broad stack migration. The prior `2026-09-01-security-hardening.md` plan was rechecked: row locking, restricted routes, registration bounds/throttling, env secrets and non-root/private-network fixtures already existed; its unchecked boxes were not treated as instructions to repeat resolved work.

## Findings and disposition

Severity is based on demonstrated preconditions/impact; signed malformed claims require access to the trusted signer/same-key issuance, not an ability to forge RSA. No unsigned-token authentication bypass or caller-controlled role elevation was found in tested flows.

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
| C16 | Operational / C,I,A | CLASSIFIED FOR LOCAL SCOPE; PUBLIC PREREQUISITES OPEN | Old cached DB/Redis image packages matched security advisories; many fixed by updated official images. Remaining component matches require applicability review; no confirmed auth exploit | Updated/pinned Compose digests, fresh 47-test fixture suite + rescan; critical-match triage below, no blanket suppression or distro migration |
| C17 | Medium / A,I | FIXED | Issuer emitted stored ANALYST while own verifier allowed only USER; invalid stored roles could also be signed | Shared exact USER/ANALYST allowlist for issuance/validation; JWT red→green and HTTP login/refresh/me plus public injection regression; no admin API |
| C13 | Operational / A,I | REQUIRED BEFORE EXPOSURE | No automatic retention/session cap; DB superuser local default; single signing key; legacy local-zone audit timestamps; proxy/NAT shared budgets | Procedures and explicit prerequisites in operations/identity contract. No purge, admin subsystem or silent timestamp/account migration added |

### Reproduction and verification ledger

- Baseline: 6 tests passed after Docker sandbox elevation; initial restricted run reported environment error, never PASS.
- First adversarial campaign: 12 tests / 6 failures, proving claims/JWKS/input/reset/UA issues ([log](evidence/reproductions.log)).
- Registration/refresh/Redis reproductions: duplicate 500s, orphan TTL, successor expiry extension ([log](evidence/concurrency-reproductions.log)); signer failure demonstrably consumed token ([log](evidence/signing-reproduction.log)).
- Body/disabled-LLM cases: 400 instead of early 413 for oversized JSON, local outgoing call with empty key ([log](evidence/resource-reproductions.log)).
- Independent review: blocked IP affected victim budget and trickle lasted ~20 s ([log](evidence/review-reproductions.log)); regression later passed with real cancellation. The first attempt at a manual deadline still drained HttpURLConnection and failed; the implementation was replaced, not the time expectation relaxed.
- Intermediate errors were corrected: Clock bean initialization cycle, JJWT 0.12.5 registry API difference, Testcontainers 2.x non-generic PostgreSQL class, Spring 7's `CONTENT_TOO_LARGE` enum alias (HTTP remains 413), and strict header-before-payload parsing. A targeted unit run was blocked by sandbox Mockito instrumentation and rerun with elevation. These transient runs do not establish passing checkpoints.
- Suites grew through 26, 29 and 33 passing tests; one later 39-test suite failed trickle cancellation, and a 41-test run caught compressed-header parsing order in classes compiled before the source correction. Final evidence must come from the fresh clean verification below.

### Supporting standards and official sources (consulted 2026-10-08)

[OWASP ASVS 5.0.0](https://github.com/OWASP/ASVS/blob/master/5.0/docs_en/OWASP_Application_Security_Verification_Standard_5.0.0_en.json): V6.1.1/V6.3.1 rate-control documentation/enforcement, V6.2.8 exact password verification, V6.2.9 long passwords; V6.3.8 enumeration is not fully satisfied because registration intentionally returns 409 and timing equality is not proved. This is supporting guidance, not ASVS certification or full level compliance.

[OWASP API Security 2023](https://api-security.owasp.org/editions/2023/en/0x00-header/): API2 authentication, API4 bounded resources, API8 deployment configuration, API10 optional upstream data. [OWASP password storage](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html) supports the selected 19 MiB Argon2id baseline, not a hardware-independent security guarantee.

[Redis INCR](https://redis.io/docs/latest/commands/incr/) documents the combined-counter TTL race and Lua remedy. [RFC 7518](https://www.rfc-editor.org/rfc/rfc7518.html) defines unsigned RSA encoding. [JJWT upstream](https://github.com/jwtk/jjwt) documents parsing; effective 0.12.5 behavior is verified by tests, not assumed from latest examples.

[Apache Tomcat official advisories](https://tomcat.apache.org/security-11.html): OSV matches CVE-2026-65905, CVE-2026-65182, CVE-2026-68525 require configurations absent here; patch 11.0.26 also includes later protocol fixes. [Spring CVE-2026-47877](https://spring.io/security/cve-2026-47877/) concerns an OAuth authorization-server consent page absent in Cypher, and effective Security 7.1.1 is patched. [Jackson advisory](https://github.com/FasterXML/jackson-databind/security/advisories/GHSA-wv8q-qhhj-9h54) requires polymorphic fallback not enabled in these DTOs; patched BOMs nevertheless remove old component matches. [BC releases](https://www.bouncycastle.org/download/bouncy-castle-java/) provide 1.86; [CVE-2025-8885](https://github.com/bcgit/bc-java/wiki/CVE%E2%80%902025%E2%80%908885) was already fixed before 1.78.1 and concerns untrusted ASN.1, not this password path. No CVE is inferred from age alone.

Evidence: [initial dependency tree](evidence/dependencies.txt), [final dependency tree](evidence/dependencies-final.txt), [initial post-patch OSV scan](evidence/osv-remediated.json), [final OSV scan](evidence/osv-final.json): 164 Maven artifacts queried, zero final matches. OSV is a secondary index, not a guarantee of complete advisory coverage; official sources/applicability take precedence. An actual image scan was subsequently run with official Trivy; results and binary-JRE coverage limitations are recorded below. Maven Wrapper distribution SHA-512 matched official Maven Central and SHA-256 is pinned ([evidence](evidence/wrapper.json)); cached installations are not revalidated automatically on every invocation.

## Tested scope and remaining checks

JWT adversaries are bounded deterministic cases plus a small malformed HTTP campaign, not exhaustive fuzzing. Unit tests cover numeric types, exact expiration/skew, missing/wrong claims, unsigned/altered/other-key/algorithm, compressed/duplicate headers, large inputs, URLs not controlling trust, invalid keystore config. There is no demonstrated role-protected 403 route (N/A); no browser UI/cookies/CORS added. Access ownership is the signed UUID, and HTTP me fields are constrained.

Real PostgreSQL/Redis tests cover registration/login/me/JWKS/refresh, hash-only rotation state, three 8-way refresh races, 5-way duplicate registration, signer/login-audit rollback, Redis pause/recovery and PostgreSQL exclusive-lock timeout/recovery. This does not prove every failure mode (e.g. a network partition mid-commit), process-crash durability or unlimited availability. Refresh replay only rejects old credentials; loss after commit requires reauthentication. Account budgets across multiple admitted IPs remain an abuse/availability trade-off.

Optional LLM is tested solely with local controlled responses, including actual drip cancellation; no Anthropic call or spend. GeoIP tests use missing/corrupt data and mocked coordinates; licensed MaxMind accuracy/live coverage is not validated. Audit data and LLM text remain sensitive/untrusted; timestamp-zone limitations and retention are operator decisions. No notification/MFA/theft-detection completeness is claimed.

Independent Java Spring/Nimbus validates real HTTP tokens/JWKS and rejects foreign issuer/audience. Full Ratchet ownership/integration and .NET/Keystone remain **BLOCKED/outside consumer implementation scope**; SDK absent, Keystone is a plan. Exact pending files/tests are in [identity contract](identity-contract.md). Nexa was not audited or used.

## Evidence locations

References below describe the remediated working tree; earlier behavior is recorded by red reproductions and the starting commit. Public source/configuration hashes will be saved in `evidence/source-manifest.json`; no `.env` or real keystore enters that manifest.

| Findings | Source / regression location |
|---|---|
| C01 | `src/main/java/com/augustopugliano/cypher/service/JwtService.java:90`; corresponding named tests in `src/test/java/com/augustopugliano/cypher/` |
| C02 | `src/main/java/com/augustopugliano/cypher/controller/JwksController.java:28`; corresponding named tests in `src/test/java/com/augustopugliano/cypher/` |
| C03 | `src/main/java/com/augustopugliano/cypher/service/LoginService.java:60`; corresponding named tests in `src/test/java/com/augustopugliano/cypher/` |
| C04 | `src/main/java/com/augustopugliano/cypher/service/RateLimitService.java:22`; corresponding named tests in `src/test/java/com/augustopugliano/cypher/` |
| C05 | `src/main/java/com/augustopugliano/cypher/service/UserService.java:34`; corresponding named tests in `src/test/java/com/augustopugliano/cypher/` |
| C05 | `src/main/java/com/augustopugliano/cypher/config/RequestBoundsFilter.java:14`; corresponding named tests in `src/test/java/com/augustopugliano/cypher/` |
| C06 | `src/main/java/com/augustopugliano/cypher/service/RefreshTokenService.java:70`; corresponding named tests in `src/test/java/com/augustopugliano/cypher/` |
| C07 | `src/main/java/com/augustopugliano/cypher/service/LlmExplanationService.java:30`; corresponding named tests in `src/test/java/com/augustopugliano/cypher/` |
| C09 | `src/main/java/com/augustopugliano/cypher/service/AnomalyDetectionService.java:57`; corresponding named tests in `src/test/java/com/augustopugliano/cypher/` |
| C12 | `src/main/java/com/augustopugliano/cypher/config/SecurityConfig.java:26`; corresponding named tests in `src/test/java/com/augustopugliano/cypher/` |

## Verification before the bounded closeout (historical record)

`./mvnw clean verify` on 2026-10-09 finished **47 tests, zero failures/errors/skips, BUILD SUCCESS, 88 seconds** ([complete log](evidence/final-verify.log)). This is a fresh compile/test/package invocation, not cached reports or skipped tests. The baseline commit is unchanged; patches are local in the audit branch. A read-only independent review found account-budget poisoning, drip-response timeout and load-response classification defects; all were fixed and regressed, not accepted.

### Local load results

The suite invokes `python3 scripts/security/load.py --url http://127.0.0.1:<fixture-port> --fixture-pid <test-jvm> --output target/security-load.json` only against its disposable app/DB/Redis. It uses 32 synthetic identities and distinct loopback source addresses; production-default limits remain active, LLM disabled. Fixture setup has 64 requests, measured phases 160, recovery 2, **226 total in 12.655 seconds**. Measured statuses: 72×200, 32×201, 32×401, 24×429; no unexpected status, 5xx or timeout. No invalid credential succeeds. New recovery registration/login succeed and database assertions pass (unique users, hash lengths, single rotation linkage, inherited expiry, <=10 DB connections).

Machine/resource evidence: [machine](evidence/machine.json). Budget was fixed before load: concurrency <=8, campaign <=60 seconds, HTTP <=5 seconds, >=2 GiB available host RAM, JVM RSS <=2 GiB, stop after >2 server errors/timeouts (any unexpected response fails the final check). Per-phase available-memory check and post-load database invariants are enforced. CPU percentages are for the JVM process and may exceed 100% on this eight-CPU machine; they include fixture/JIT/GC overhead. JVM RSS is sampled per phase, not an instantaneous peak; PostgreSQL/Redis CPU/queue internals are not instrumented. Optional executor saturation has a separate deterministic regression. Small samples make p95/p99 coarse; these seconds-long phases are a bounded adversarial campaign, not sustained capacity or DDoS certification.

| Phase | Concurrency | Requests | Seconds | Total rps | JVM RSS MiB | JVM CPU % |
|---|---:|---:|---:|---:|---:|---:|
| baseline | 1 | 16 | 1.354 | 11.821 | 648.6 | 124.12 |
| step-2 | 2 | 32 | 1.403 | 22.809 | 649.3 | 280.84 |
| step-4 | 4 | 48 | 1.684 | 28.51 | 955.6 | 441.31 |
| spike | 8 | 64 | 0.94 | 68.115 | 1014.6 | 567.27 |

Latency in ms. Admitted p95 excludes cheap 429s; it is not inferred from total throughput. Full sample/status/resource data: [JSON](evidence/load-final.json), [driver](evidence/load-driver.log).

| Phase | Operation | p50 | p95 | p99 | Admitted p95 |
|---|---|---:|---:|---:|---:|
| baseline | login_valid | 96.318 | 119.948 | 119.948 | 119.948 |
| baseline | login_invalid | 98.056 | 156.807 | 156.807 | 156.807 |
| baseline | register | 90.579 | 102.512 | 102.512 | 102.512 |
| baseline | refresh | 21.204 | 30.705 | 30.705 | 30.705 |
| step-2 | login_valid | 99.41 | 169.443 | 169.443 | 169.443 |
| step-2 | login_invalid | 97.767 | 153.21 | 153.21 | 153.21 |
| step-2 | register | 95.962 | 152.785 | 152.785 | 152.785 |
| step-2 | refresh | 20.494 | 32.773 | 32.773 | 32.773 |
| step-4 | login_valid | 190.546 | 232.753 | 232.753 | 232.753 |
| step-4 | login_invalid | 170.981 | 204.781 | 204.781 | 204.781 |
| step-4 | register | 150.915 | 206.534 | 206.534 | 206.534 |
| step-4 | refresh | 31.674 | 58.236 | 58.236 | 58.236 |
| spike | login_valid | 17.514 | 359.488 | 359.488 | 359.488 |
| spike | login_invalid | 22.913 | 343.799 | 343.799 | 343.799 |
| spike | register | 25.236 | 274.111 | 274.111 | 274.111 |
| spike | refresh | 53.913 | 112.066 | 112.066 | 112.066 |

Three synchronized eight-client refresh races each return exactly one 200 and seven 401 with persisted lineage assertions. Five concurrent registrations return one 201 and four 409. This finite repetition does not prove absence of all intermittent failures.

### Previous checkpoint disposition

| Checkpoint | Status | Command / result / evidence |
|---|---|---|
| CP0 baseline | PASS | `./mvnw test` with Docker access: 6/6; clean starting commit, generated fixtures; [baseline](evidence/baseline.log) |
| CP1 surface/plan | PASS | Source/caller inspection, threat model and findings above; failing reproductions linked; unchanged public routes/response fields and documented compatibility |
| CP2 own identity + Java contract | PASS | `./mvnw clean verify`: JwtContractTest + real HTTP independent Spring/Nimbus consumer; strict invalid claims, public unsigned JWKS, no injected role. Full Ratchet/Keystone/.NET consumer integration remains BLOCKED, not part of this PASS |
| CP3 concurrent integrity | PASS | Same command: repeated 8-way refresh, 5-way registration, exact responses and PostgreSQL rows, signer/audit rollback, replay/successor and exact expiration |
| CP4 tested abuse/degradation | PASS | Same command: Lua concurrency/TTL repair, valid-login budgets, forwarding spoof, body/trickle bounds, Redis pause and PG lock 503/recovery, disabled/failing/saturated LLM; broader distributed/slow-header cases remain outside verified scope |
| CP5 complete operational assurance | BLOCKED | Suite, actual Spring context restart, synthetic pg_dump/restore, load and Maven OSV scan pass. Container verification recorded below. Trivy scans completed for app/DB/Redis; app has zero matches. Infrastructure image disposition is detailed below; hosted CI not run. No omitted check is promoted to PASS |
| CP6 unrestricted favorable closure | BLOCKED | Own reproduced high finding C03 fixed; C08 historical credential non-use/revocation cannot be verified externally. Owner prerequisites and consumer validation remain open; no risk accepted on owner's behalf |

**Verdict:** suitable for a finite, isolated local demo using synthetic identities, generated development keys and loopback exposure within the tested budget. Public exposure/production readiness and complete ecosystem integration are **not approved by this evidence**. Historical credentials must be verified/rotated as applicable, patched runtime/image scan and operational controls completed, and consumer validators exercised. No deployment/push/key rotation or personal volume deletion occurred.

To resume blocked checks: finish infrastructure advisory applicability and rerun the image scanner command in [operations](operations.md), run the added GitHub workflow after an owner-authorized push, execute `.NET` fixture/consumer tests described in [identity contract](identity-contract.md), and record the owner's historical-credential verification without disclosing values. Retention/proxy/restricted DB role and rotation prerequisites are described in operations; no consumer changes were made here.

### Container build

`docker build -t cypher-security-audit:20261009 .` passed after a reproducible Wrapper checksum rejection: the JDK build stage lacked unzip and selected TAR.GZ despite a checksum pinned for ZIP. Adding unzip only to the build stage retains checksum enforcement ([failed reproduction](evidence/image-build-reproduction.log), [successful build](evidence/image-build.log)). Image ID `sha256:02abd0ee2da2de33a5b2485fecb99cac210ce38721a17b03b514b1ad3b739be9`; configured runtime user `cypher`. Packaging inside Docker deliberately skips tests; the separate clean 47-test run is the final test evidence. No image was pushed or deployment created. The build uses recorded base digests in its log but tags are not permanently pinned in source.

### Additional closure checks

A fresh 46-test clean suite passed on 2026-10-09 after adding explicit unknown/expired/revoked refresh rejection and a real PostgreSQL constraint failure on successor INSERT. The latter returned 503, retained the original unconsumed token with no successor, and succeeded after removing the fixture-only constraint ([log](evidence/refresh-closure-verify.log)). A repeat measured load is recorded separately in [repeat JSON](evidence/load-repeat.json); the tables above identify the final 47-test campaign, not a mixed aggregate. The final 47-test suite also passes the log-privacy regression.

Runtime smoke command `docker run --rm --entrypoint sh cypher-security-audit:20261009 -c 'id -u; java -version'` returned UID 1000 and Temurin JRE 21.0.12.1+1. This tests runtime identity/version, not full Compose deployment. An isolated Trivy attempt scans the exported image without mounting the Docker socket or secrets; its result will be recorded separately.

The validation privacy test failed before correction: Spring's default warning copied the synthetic password into logs ([reproduction](evidence/log-privacy-reproduction.log)). Generic 400 advice now handles validation/malformed-body exceptions without including rejected values. Normal incorrect credentials remain generic 401. No real passwords were collected in this investigation.

Trivy official image digest `sha256:af6acf9a6b85dfe389a1941505c0ce9efef52a4719635e1a962f022a3d855daa` scanned the actual first exported image: two MEDIUM Alpine matches, no Java matches ([raw JSON](evidence/image-scan-before.json)). [libpng's official advisory](https://github.com/pnggroup/libpng/security/advisories/GHSA-qvg3-h654-xq3j) confirms CVE-2026-46675 in <=1.6.58, fixed 1.6.59; [zlib upstream report](https://github.com/madler/zlib/issues/1310) records CVE-2026-85091, and Alpine's patched package version is supplied by the scan. These paths are not demonstrated exploitable through Cypher; the Docker runtime upgrades libpng/zlib rather than assuming the newest Temurin tag contains every OS patch. Consulted 2026-10-09. The final Cypher image rescan returned zero Alpine/JAR matches ([JSON](evidence/image-app-final.json)). This result is database/time limited, not an absence-of-vulnerabilities guarantee.

Final log-privacy regression and all 47 tests pass in [final clean verification](evidence/final-verify.log). The final Docker build includes that advice and targeted Alpine upgrades ([build](evidence/image-final-build.log)); final image ID `sha256:f9c7b64473f2a2c1c7fd510d120d296678e1a970a5c132188cb2e41a3bcf535a`. [Runtime smoke evidence](evidence/runtime.log) confirms UID 1000 and JRE 21.0.12.1+1, matching the [official Temurin 21 release](https://github.com/adoptium/temurin21-binaries/releases) consulted 2026-10-09. Maven/JAR scanning is not a binary audit of every native JRE path.

### Infrastructure image scan / applicability

The initial cached `postgres:16` image (`sha256:e17e86066e5ef83e0952a9347f5c792b7ece00972e2aa787a6986f471b3dd3d5`) returned 571 package matches (14 CRITICAL, 141 HIGH); cached `redis:7` (`sha256:71da9275c5f3fcb97d0fa0c8c5b36cc995327265420f17a04bfd544f458059f7`) returned 258 (4 CRITICAL, 57 HIGH). These are component matches, **not 829 confirmed Cypher vulnerabilities**. Complete unfiltered evidence: [PostgreSQL](evidence/image-postgres.json), [Redis](evidence/image-redis.json). App image has zero final matches. Trivy version 0.75.0, pinned scanner digest above; fresh public vulnerability DB plus Java DB. No scan accessed `.env`, personal volumes or keystore.

Critical-match triage against official sources (2026-10-09):

- [CVE-2023-45853 / Debian](https://security-tracker.debian.org/tracker/CVE-2023-45853): Redis Bookworm zlib1g is a binary-package false positive for MiniZip; Debian notes the vulnerable contrib code is not built/provided in that binary. No broad suppression file added.
- [CVE-2026-8376 / Debian](https://security-tracker.debian.org/tracker/CVE-2026-8376): requires compiling attacker-controlled Perl expressions on a **32-bit** build; these fixtures are amd64 and auth does not invoke Perl. The component is still tracked/patched when available.
- [CVE-2026-13221 / Debian](https://security-tracker.debian.org/tracker/CVE-2026-13221) and [CVE-2026-42496 / Debian](https://security-tracker.debian.org/tracker/CVE-2026-42496): respectively huge Perl regex tries and unsafe Perl Archive::Tar extraction. HTTP credentials use Java validation/Argon2 and parameterized JPA, with no Perl/tar caller. Not demonstrated reachable from auth, not a license to run untrusted scripts/archives inside infrastructure containers.
- [CVE-2026-6653 / Debian](https://security-tracker.debian.org/tracker/CVE-2026-6653): libxml2 UAF remains a distro issue (Debian labels it minor/postponed). Cypher accepts bounded JSON and does not submit attacker-controlled SQL/XML to PostgreSQL. Direct privileged DB/XML usage is outside that boundary and remains an operational risk.
- [CVE-2025-68121 / official Go](https://pkg.go.dev/vuln/GO-2026-4337): Go crypto/tls resumption; scanner location is `usr/local/bin/gosu`. [gosu's source](https://github.com/tianon/gosu/blob/master/main.go) switches process credentials/execs and has no TLS handshake flow. No exploit is demonstrated from the mere embedded stdlib version; broader Go findings require symbol/caller analysis.

Remaining component matches are preserved without blanket acceptance. The bounded closeout below completes all 43 HIGH/CRITICAL identifier classifications; MEDIUM/LOW/UNKNOWN notices remain outside that additional round. Before public operation, preserve the reviewed boundaries and follow current vendor patches. No automatic distro switch (e.g. Debian→Alpine) was made: PostgreSQL libc/collation differences can affect existing indexes/data and need an isolated migration check. Initial image-update attempts encountered Docker Hub TLS/CDN timeouts; a permission-review timeout was retried successfully, not treated as unsafe or as user approval. No image update was deployed.

Official image updates completed after retry. Compose now pins the reviewed current image digests: PostgreSQL `sha256:ca0bd484cb98bf4b24eb1010e73fb3fcbd6714d240fbc1a10eea5b7dbecb641d`, Redis `sha256:4fa24486b8bcca8eec45ee0eb166edc674795e53a2b53d1a9ef263eecebaac85`. No major server/distro switch or deployment occurred. The final 47-test suite passed on fresh fixtures using these newly cached official images; existing personal databases remain untouched.

Current rescan: PostgreSQL **363 component matches** (2 CRITICAL, 82 HIGH, 123 MEDIUM, 134 LOW, 22 UNKNOWN); Redis **229** (1 CRITICAL, 49 HIGH, 99 MEDIUM, 79 LOW, 1 UNKNOWN). [PostgreSQL JSON](evidence/image-postgres-current.json), [Redis JSON](evidence/image-redis-current.json). Old Perl critical matches disappear. The remaining Redis critical is the documented MiniZip binary false positive; PostgreSQL critical matches are libxml2/XML and gosu's embedded Go TLS. PostgreSQL's 22 fixable HIGH/CRITICAL matches all refer to gosu's embedded stdlib; Redis has zero fixable HIGH/CRITICAL matches. Merely recompiling gosu to clean a version-only report is not an auth fix; call-path analysis is required. No global ignore rule or claim of 592 reachable vulnerabilities is made. This earlier unresolved classification is superseded by the bounded closeout below; public operational requirements remain open.

Exact scan reproduction: export each pinned image with `docker save -o /tmp/<owned-image>.tar <image-reference>`; run `docker run --rm -v /tmp/<owned-image>.tar:/scan/image.tar:ro ghcr.io/aquasecurity/trivy@sha256:af6acf9a6b85dfe389a1941505c0ce9efef52a4719635e1a962f022a3d855daa image --input /scan/image.tar --scanners vuln --timeout 3m --format json`. This gives the current public DB result, which may change. Before exposure, revalidate the classified preconditions against the intended runtime, provision reviewed images/restricted roles and rerun the suite/restore tests; do not replace or delete a live data volume to eliminate scanner output.

Final recorded verification: `./mvnw clean verify` on updated PostgreSQL/Redis images passes **47/47, zero failures/errors/skips, 88 seconds**. `git diff --check` passes. `docker compose --env-file .env.example config --quiet` validates without showing expanded configuration or reading personal `.env`. Server versions are captured in [PostgreSQL](evidence/postgres-version.txt) and [Redis](evidence/redis-version.txt). Baseline commit remains unchanged; all remediation is reviewable as local changes on the audit branch, no commits/push/deployment performed. `evidence/source-manifest.json` records public source/configuration/document hashes to identify this uncommitted tree. Tests continue to isolate `flushDb()` to their exclusively owned disposable Redis fixture.

## Bounded closeout — 2026-10-09

Scope is unchanged: own Cypher remediation, generated synthetic fixtures, finite local loopback demo. Ratchet/.NET/Keystone consumer integration and public deployment prerequisites are distinct pending work. No administrative subsystem, distro switch, suppression file, real credential rotation, push or deployment was added.

### Roles

Keystone's planned local `ANALYST` provisioning exposed a reproducible contradiction: `generateToken()` signed ANALYST but `getClaims()` rejected it. It also signed unsupported stored roles. Two targeted regressions failed before the fix ([red](evidence/role-reproduction.log)); the shared exact `USER`/`ANALYST` predicate now governs both operations ([12 JWT tests](evidence/role-regression.log)). HTTP tests cover both roles through login/rotation/me, and caller-injected ANALYST remains USER at registration; existing ADMIN injection regression remains. Authorized provisioning is a documented exact-UUID local SQL action on a synthetic account, not an HTTP route. No real account was modified. Consumers still must authorize their own endpoints; previous JWT roles last until expiry/skew.

### Infrastructure classification completed

All **43 unique HIGH/CRITICAL identifiers** in the recorded current PG/Redis scans are mapped to preconditions, actual configured exposure, correction status and a proposed decision in [complete classification](evidence/infrastructure-classification.json). It includes every identifier, package/installed version, image and official source; coverage is asserted against the raw scan set. [Official advisory snapshots](evidence/official-infrastructure-advisories.json) verify all 43 Go/Debian records (no blocked source reads). Consulted 2026-10-09. No severity-only suppression or owner risk acceptance.

This is the **configured Compose + disposable same-image probe** exposure model, not inspection of personal live containers. [PostgreSQL probe](evidence/postgres-exposure.txt) confirms homed/TPM daemon/devices absent; [Redis probe](evidence/redis-exposure.txt) confirms tls-port=0. Default capability mask excludes SYS_ADMIN; no privileged/host namespace/socket/device mount is configured. Default fstab does not authorize user mounts. Web input flows through bounded JSON and parameterized JPA, not shell/SQL/XML execution. A compromised host, directly exposed DB, arbitrary SQL console or a new parsing feature changes these conclusions.

| Component / identifiers | Required precondition | Exposure in this local profile | Correction available / proposed decision |
|---|---|---|---|
| Debian zlib1g / CVE-2023-45853 | Vulnerable MiniZip binary and crafted archive metadata | Source-package match; Bookworm binary excludes vulnerable contrib code per Debian | Binary false positive for this image. No demo blocker; reassess added minizip/pyminizip, no general ignore |
| gosu embedded Go / 22 IDs listed individually in JSON | Affected TLS/x509, HTTP/URL, mail/MIME, XML/template, os.Root or CNAME functions processing malicious input | Process UID switcher with trusted startup arguments; these callers absent. Windows-specific panic also not this Linux profile | Official fixed compiler ranges recorded per ID; requires upstream gosu rebuild, not apt replacement of embedded Go. No auth-path blocker; recheck changed callers and upstream rebuild before an exposed deployment |
| util-linux / 53613, 76642, 78408–78410 (all CVE-2026) | Local shell plus authorized fstab/user/X-mount or privileged nsenter/cgroup operation, writable source/target path | No HTTP shell, user mount, SYS_ADMIN/privileged mode or host namespace/device access | 53613 fixed in Trixie; later issues have upstream fixes but stable vendor gaps. Keep prerequisites absent; do not import unstable packages/change distro. Local demo permitted; privileged/untrusted-shell deployment requires patch/isolation review |
| systemd/udev / CVE-2026-16742 | Running homed and logged-in homed-managed user | homed executable/service absent; library source match | Upstream fix, stable gaps; no blocker under absent-service condition. Reassess if homed/host services added |
| GnuPG / CVE-2026-24882 | TPM-backed keys through tpm2daemon PKDECRYPT | Daemon/devices absent; Java signing is unrelated | Fixed upstream, Trixie pending; no blocker here. Patch before adding TPM decrypt workloads |
| ncurses / CVE-2025-69720 | infocmp on malicious terminfo | Not invoked by auth/server startup | Upstream fix; stable status in snapshot. No blocker; forbid untrusted terminal tooling until patched |
| gzip / CVE-2026-41992 | Crafted LZW/LZH chain in one gzip command | No archive/upload shell flow | Upstream/vendor status recorded, stable gap. No blocker here; patch before introducing untrusted archives |
| libacl / CVE-2026-54369 | Privileged ACL operation on attacker-writable ancestor/symlink path | API cannot select paths/ACLs; operator-owned volumes, no untrusted local shell | Upstream 2.4.0, stable gap. Keep ownership/mount boundary; local demo permitted, untrusted shared-path ACL processing blocked pending patch/review |
| Perl Archive::Tar / CVE-2026-9538 | Parse attacker-sized archive entries | No Perl/tar ingestion; synthetic backup uses pg_dump/restore | Fixed upstream/unstable; stable gap. No blocker; patch before untrusted archive processing |
| OpenSSL / CVE-2026-84782 | DTLS fragmented/retransmitted handshake with suspended writes | Redis TCP, tls-port=0; optional Redis TLS is also TCP, not DTLS | Official fix, no Bookworm fix at snapshot. No DTLS exposure; no local blocker. Direct public Redis remains prohibited independently |
| libxml2 / CVE-2026-6653, 74860, 86138–86140, 86142–86144 | Malicious XML/XPointer/XInclude/output; 74860 additionally Python SAX bindings | PG links libxml2, but auth submits no XML SQL; no Python binding. Direct SQL limited to trusted local operator | Upstream 2.15.4 fixes, stable vendor gaps. No blocker for synthetic auth demo. Public API requires private DB + restricted app role; untrusted SQL/XML exposure/ingestion blocked until patched or separately reviewed isolation |

These are proposals grounded in absent prerequisites, not permission to ignore vulnerable components. They do **not** individually block the measured local synthetic demo. Before public API exposure, verify that the absent preconditions stay absent, apply available supported vendor patches, restrict the DB role/network, and secure TLS/proxy/runtime/retention. A public API alone does not make gosu's uncalled Go parsers or DTLS reachable. An owner must decide any intended feature requiring an affected path; no risk is accepted here.

### Historical credential action

C08 is still **BLOCKED (external owner confirmation)**. The owner was asked to inventory PostgreSQL endpoints/roles, `.env`/Compose/IDE/service secret overrides, any previously owned remote/demo installations and CI stores; then check reuse in other credentials without disclosing values. Exact required confirmation and the prepared interactive rotation/recovery procedure are in [operations](operations.md#historical-credential-verification--owner-action). Changing POSTGRES_PASSWORD does not rotate a role in an existing volume, and changing a password does not terminate existing sessions. No secret value or hash is requested; no actual rotation took place. Generated fixture DB/key credentials are independent of the historical values, so this does not invalidate the synthetic demo evidence.

### Sustained admitted work

The predeclared campaign is **180 seconds**, one sequential workflow every three seconds, concurrency **1**, on this 8-CPU/15.6-GiB workstation. Sixty independent synthetic IP/account workflows each perform register, correct login, incorrect login, refresh. The default 5-attempt/5-minute limits and refresh limit remain active: no reset, window change or diagnostic profile. This represents differentiated clients within their normal budgets; it does not measure one NAT sharing an IP or distributed-abuse resistance.

Stop/acceptance budget: HTTP 5 seconds; entire driver <210 seconds; JVM sampled RSS <2 GiB, available host memory >2 GiB; stop on any unexpected response. Require all 240 measured requests admitted and per-operation/per-minute admitted p95 <1 second (a generous small-demo criterion compared with the existing ~0.1-second sequential baseline, not a production SLO). Five seconds of cooldown then synthetic recovery register/login; DB invariant assertions follow. Driver missing-mode regression failed before implementation ([red](evidence/sustained-reproduction.log)).

Observed: **180.000 s measurement, 240/240 admitted, 1.333 requests/s**, 60×201, 120×200, 60×401; **zero 429/5xx/timeouts/unexpected responses**. Recovery adds one 201 and one 200, total wall 185.247 s. RSS sampled every cycle: 414.79→516.74 MiB, maximum 516.74 MiB; minimum available RAM 7821.69 MiB. This ~102-MiB RSS increase during warmup does not prove a leak or stable long-run memory. Peak interval JVM CPU 229.94% (about 2.3 logical CPUs, includes JIT/GC/test process); no process CPU hard quota or DB/Redis CPU profiler is claimed.

| Operation (60 admitted samples each) | p50 ms | p95 ms | p99 ms |
|---|---:|---:|---:|
| Correct login | 97.329 | 162.246 | 670.997 |
| Incorrect credentials | 91.185 | 133.143 | 294.961 |
| Register | 91.090 | 128.687 | 1117.684 |
| Refresh | 18.843 | 34.982 | 94.634 |

The 1.118-second registration sample is included, not discarded as warmup. All minute-specific p95s meet the criterion. Samples/resources/per-minute distributions: [JSON](evidence/sustained-final.json). These minute-scale, concurrency-one results are a sustained **small demo** check, not max capacity, a high-concurrency claim or production benchmark.

Post-run DB: **61 users, 121 audit rows, 121 hashed refresh rows, 60 revoked predecessors**; no duplicate email/successor branch, missing successor, inconsistent revocation/absolute expiry or wrong hash length; <=10 DB connections and recovery account present. Real row assertions and HTTP statuses pass in the integration test.

### Final closeout checkpoints

| CP | Status for measured local scope | Evidence / remaining boundary |
|---|---|---|
| CP0 | PASS | Original six-test baseline and synthetic fixtures retained |
| CP1 | PASS | Original threat model/patch trace plus bounded role/infra closeout |
| CP2 | PASS | Both roles, public registration restriction, JWT adversaries and independent Java JWKS contract; full Ratchet/.NET integration remains pending |
| CP3 | PASS | Real DB races, replay, signer/storage/audit rollback and persisted invariants |
| CP4 | PASS | Limits/TTL, bounded input/dependency failures, optional LLM and sustained admitted traffic |
| CP5 | PASS (local) | 51-test clean suite, restart/restore, dependency/image scans and all critical/high classifications; hosted CI and public deployment are not claimed |
| CP6 | PASS (synthetic local stage only) | Own corrections traced/tested; C08 owner verification and public prerequisites remain BLOCKED/open separately, not accepted risks |

**Stage verdict:** own Cypher remediation is ready for a finite, isolated synthetic **local demo within the measured budget**, and the next repository work can focus on Ratchet. No statement of complete ecosystem integration or public/production readiness follows. C08 remains externally blocked for previously used/real credentials; Ratchet subject ownership and issuer/audience/skew enforcement, .NET role middleware and their consumer tests are pending. Public TLS/proxy/DB role/retention/key/runtime boundaries still require implementation/owner decisions.

Final clean command `./mvnw clean verify`: **51 tests, zero failures/errors/skips, BUILD SUCCESS, 4 min 26 s**, [complete log](evidence/closeout-verify.log). Read-only closeout code review found no concrete issues; it did not run Maven/Docker itself. Changes are prepared locally for a reviewable commit; no commit/push/deployment is executed automatically.

Final image verification: `docker build -t cypher-security-audit:20261009-closeout .` passed ([build](evidence/closeout-image-build.log)); image ID `sha256:c80929cdb3612df2f0ebb8363a1f5d775a01b83c62bbb33ad9850c7c5f505e5f`. Trivy 0.75.0 using the pinned scanner digest and exported final image returned **zero Alpine/JAR matches** ([raw JSON](evidence/closeout-image-scan.json), [scanner log](evidence/closeout-image-scan.log)). This includes the role correction, uses the cached current public vulnerability databases and does not replace the separate 51-test clean run. No Compose deployment is claimed.

Final runtime smoke `docker run --rm --entrypoint sh cypher-security-audit:20261009-closeout -c 'id -u; java -version'` returned **UID 1000 / Temurin JRE 21.0.12.1+1** ([evidence](evidence/closeout-runtime.log)). `git diff --check` is clean. The authorized source, tests, configuration and evidence are staged for a reviewable commit on `codex/security-audit-2026-10-08`; HEAD remains the recorded baseline. The public-file SHA-256 manifest excludes ignored modernization logs, personal secrets and generated build output.

Commit preparation detected trailing spaces emitted by Maven/container loggers in previously untracked evidence. Only line-end spaces/tabs in saved `.log` files were normalized; test results/messages remain intact. Staged whitespace verification was then rerun, without a general suppression rule.
