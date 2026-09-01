# Security Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Remove the confirmed secret and deployment exposures, and make authentication controls safe under concurrent use.

**Architecture:** Keep the existing Spring MVC/JPA services. Use a database row lock to consume a refresh token once, reuse Redis for registration throttling, and use Docker network isolation instead of adding services.

**Tech Stack:** Java 21, Spring Boot, Spring Data JPA, Redis, Docker Compose, JUnit.

**Spec:** User-approved security-audit remediation, 2026-09-01.

## Global Constraints

- No new runtime dependencies.
- Do not place credentials or private keys in tracked files.
- Do not rotate the deployed signing key automatically.
- Tests must not require a real credential.

---

### Task 1: Make refresh-token consumption atomic

**Files:**
- Modify: `src/main/java/com/augustopugliano/cypher/repository/RefreshTokenRepository.java`
- Modify: `src/main/java/com/augustopugliano/cypher/service/RefreshTokenService.java`
- Test: `src/test/java/com/augustopugliano/cypher/AuthIntegrationTest.java`

- [ ] Add a failing concurrent-refresh test that accepts one response and rejects the replay.
- [ ] Lock the refresh-token row while `processRefresh` checks and revokes it.
- [ ] Run the focused test when Docker is available; otherwise compile it.

### Task 2: Restrict unauthenticated entry points

**Files:**
- Modify: `src/main/java/com/augustopugliano/cypher/config/SecurityConfig.java`
- Modify: `src/main/java/com/augustopugliano/cypher/controller/AuthController.java`
- Modify: `src/main/java/com/augustopugliano/cypher/service/RateLimitService.java`
- Modify: `src/main/java/com/augustopugliano/cypher/dto/RegisterRequest.java`
- Test: `src/test/java/com/augustopugliano/cypher/AuthIntegrationTest.java`

- [ ] Add failing tests for registration throttling and a rejected oversized password.
- [ ] Use the existing Redis counter with a `register_attempts:` namespace.
- [ ] Cap registration passwords at 128 characters and require 12 characters.

### Task 3: Harden runtime configuration and documentation

**Files:**
- Modify: `docker-compose.yml`
- Modify: `Dockerfile`
- Modify: `src/main/resources/application.properties`
- Modify: `README.md`
- Modify: `src/test/java/com/augustopugliano/cypher/AuthIntegrationTest.java`

- [ ] Stop publishing Redis; bind PostgreSQL to loopback; mount secrets read-only; run the app as a non-root user.
- [ ] Disable SQL logging; make schema management opt-in through `DDL_AUTO`.
- [ ] Remove the actual keystore password from tracked documentation and tests, using `KEYSTORE_PASSWORD` at runtime.
- [ ] Document permissions and key rotation without including a secret.

### Task 4: Verify

- [ ] Run `./mvnw -DskipTests package`.
- [ ] Run `./mvnw test`; report Docker availability separately from test failures.
- [ ] Review `git diff --check` and confirm no secret-like literals were added.
