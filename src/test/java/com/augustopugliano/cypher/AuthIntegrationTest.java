package com.augustopugliano.cypher;

import com.augustopugliano.cypher.dto.LoginRequest;
import com.augustopugliano.cypher.dto.RegisterRequest;
import com.augustopugliano.cypher.dto.RefreshRequest;
import com.augustopugliano.cypher.dto.TokenResponse;
import com.augustopugliano.cypher.model.User;
import com.augustopugliano.cypher.repository.UserRepository;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.client.RestTemplate;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.postgresql.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.util.Optional;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@Testcontainers
public class AuthIntegrationTest {

    private static final String TEST_KEYSTORE_PASSWORD = TestKeys.PASSWORD;
    private static final Path TEST_KEYSTORE = TestKeys.PATH;

    @Container
    static PostgreSQLContainer postgres = new PostgreSQLContainer("postgres:16")
            .withDatabaseName("cypher_test")
            .withUsername("test")
            .withPassword("test");

    @Container
    static org.testcontainers.containers.GenericContainer<?> redis = new org.testcontainers.containers.GenericContainer<>("redis:7").withExposedPorts(6379);

    @DynamicPropertySource
    static void configureProperties(DynamicPropertyRegistry registry) {
        registry.add("spring.datasource.url", postgres::getJdbcUrl);
        registry.add("spring.datasource.username", postgres::getUsername);
        registry.add("spring.datasource.password", postgres::getPassword);
        registry.add("spring.data.redis.host", redis::getHost);
        registry.add("spring.data.redis.port", redis::getFirstMappedPort);
        registry.add("cypher.jwt.keystore.location", () -> "file:" + TEST_KEYSTORE);
        registry.add("cypher.jwt.keystore.password", () -> TEST_KEYSTORE_PASSWORD);
        registry.add("cypher.anthropic.enabled", () -> "false");
        registry.add("cypher.geoip.db-path", () -> "missing-test-geoip.mmdb");
        registry.add("spring.sql.init.mode", () -> "always");
    }

    @LocalServerPort
    private int port;

    private RestTemplate restTemplate = new RestTemplate();

    private String url(String path) {
        return "http://localhost:" + port + path;
    }

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private com.augustopugliano.cypher.repository.RefreshTokenRepository refreshTokenRepository;

    @org.springframework.test.context.bean.override.mockito.MockitoSpyBean
    private com.augustopugliano.cypher.repository.LoginAuditLogRepository loginAuditLogRepository;

    @Autowired
    private org.springframework.data.redis.core.StringRedisTemplate redisTemplate;

    @Autowired
    private org.springframework.context.ApplicationContext applicationContext;

    @Test
    void unusedBootUserIsAbsentAndBasicAuthenticationCannotGrantAccess() {
        var properties = applicationContext.getBean(org.springframework.boot.security.autoconfigure.SecurityProperties.class);
        var headers = new org.springframework.http.HttpHeaders();
        headers.setBasicAuth(properties.getUser().getName(), properties.getUser().getPassword());
        assertThat(restTemplate.exchange(url("/auth/me"), org.springframework.http.HttpMethod.GET,
                new org.springframework.http.HttpEntity<>(headers), String.class).getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        assertThat(applicationContext.getBeansOfType(org.springframework.security.core.userdetails.UserDetailsService.class).size())
                .as("JWT-only Cypher must not create a default password-bearing user").isZero();
    }

    @BeforeEach
    void setUp() {
        restTemplate.setErrorHandler(new org.springframework.web.client.DefaultResponseErrorHandler() {
            @Override
            public boolean hasError(org.springframework.http.client.ClientHttpResponse response) {
                return false;
            }
        });
        loginAuditLogRepository.deleteAll();
        refreshTokenRepository.deleteAll();
        userRepository.deleteAll();
        redisTemplate.getConnectionFactory().getConnection().serverCommands().flushDb();
    }

    @Test
    void shouldRegisterUserSuccessfully() {
        RegisterRequest request = new RegisterRequest();
        request.setEmail("john@example.com");
        request.setPassword("Password123!");

        ResponseEntity<Void> response = restTemplate.postForEntity(url("/auth/register"), request, Void.class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.CREATED);
        Optional<User> user = userRepository.findByEmail("john@example.com");
        assertThat(user).isPresent();
    }

    @Test
    void shouldLoginAndReturnTokens() {
        // First register
        RegisterRequest registerReq = new RegisterRequest();
        registerReq.setEmail("jane@example.com");
        registerReq.setPassword("Password123!");
        restTemplate.postForEntity(url("/auth/register"), registerReq, Void.class);

        // Then login
        LoginRequest loginRequest = new LoginRequest();
        loginRequest.setEmail("jane@example.com");
        loginRequest.setPassword("Password123!");
        ResponseEntity<TokenResponse> response = restTemplate.postForEntity(url("/auth/login"), loginRequest, TokenResponse.class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).isNotNull();
        assertThat(response.getBody().getAccess_token()).isNotBlank();
        assertThat(response.getBody().getRefresh_token()).isNotBlank();
    }

    @Test
    void shouldRateLimitAfterTooManyAttempts() {
        // Try logging in with non-existent user 6 times
        LoginRequest loginRequest = new LoginRequest();
        loginRequest.setEmail("hacker@example.com");
        loginRequest.setPassword("wrongpassword");

        for (int i = 0; i < 5; i++) {
            ResponseEntity<String> res = restTemplate.postForEntity(url("/auth/login"), loginRequest, String.class);
            assertThat(res.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        }

        // 6th attempt should be blocked
        ResponseEntity<String> rateLimitedRes = restTemplate.postForEntity(url("/auth/login"), loginRequest, String.class);
        assertThat(rateLimitedRes.getStatusCode()).isEqualTo(HttpStatus.TOO_MANY_REQUESTS);
    }

    @Test
    void shouldRateLimitRegistrationsByIp() {
        for (int i = 0; i < 5; i++) {
            RegisterRequest request = new RegisterRequest();
            request.setEmail("register" + i + "@example.com");
            request.setPassword("LongPassword123!");
            assertThat(restTemplate.postForEntity(url("/auth/register"), request, Void.class).getStatusCode())
                    .isEqualTo(HttpStatus.CREATED);
        }

        RegisterRequest request = new RegisterRequest();
        request.setEmail("blocked@example.com");
        request.setPassword("LongPassword123!");
        assertThat(restTemplate.postForEntity(url("/auth/register"), request, String.class).getStatusCode())
                .isEqualTo(HttpStatus.TOO_MANY_REQUESTS);
    }

    @org.junit.jupiter.api.RepeatedTest(3)
    void shouldConsumeRefreshTokenOnlyOnceWhenRequestsRace() throws Exception {
        RegisterRequest registerRequest = new RegisterRequest();
        registerRequest.setEmail("refresh@example.com");
        registerRequest.setPassword("LongPassword123!");
        restTemplate.postForEntity(url("/auth/register"), registerRequest, Void.class);

        LoginRequest loginRequest = new LoginRequest();
        loginRequest.setEmail("refresh@example.com");
        loginRequest.setPassword("LongPassword123!");
        String refreshToken = restTemplate.postForEntity(url("/auth/login"), loginRequest, TokenResponse.class)
                .getBody().getRefresh_token();

        CountDownLatch start = new CountDownLatch(1);
        var requests = java.util.stream.IntStream.range(0, 8)
                .mapToObj(i -> CompletableFuture.supplyAsync(() -> refresh(start, refreshToken))).toList();
        start.countDown();
        var responses = new java.util.ArrayList<ResponseEntity<TokenResponse>>();
        for (var future : requests) responses.add(future.get(10, TimeUnit.SECONDS));
        assertThat(responses.stream().filter(r -> r.getStatusCode() == HttpStatus.OK)).hasSize(1);
        assertThat(responses.stream().filter(r -> r.getStatusCode() == HttpStatus.UNAUTHORIZED)).hasSize(7);
        var original = refreshTokenRepository.findByTokenHash(refreshService.hashToken(refreshToken)).orElseThrow();
        assertThat(original.isRevoked()).isTrue();
        assertThat(original.getReplacedBy()).isNotNull();
        assertThat(refreshTokenRepository.count()).isEqualTo(2);
        var winner = responses.stream().filter(r -> r.getStatusCode() == HttpStatus.OK).findFirst().orElseThrow().getBody();
        var successor = refreshTokenRepository.findByTokenHash(refreshService.hashToken(winner.getRefresh_token())).orElseThrow();
        assertThat(successor.getId()).isEqualTo(original.getReplacedBy());
        assertThat(successor.getExpiresAt()).isEqualTo(original.getExpiresAt());
        assertThat(successor.getTokenHash()).hasSize(64).isNotEqualTo(winner.getRefresh_token());
        assertThat(refresh(new CountDownLatch(0), refreshToken).getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        assertThat(refresh(new CountDownLatch(0), winner.getRefresh_token()).getStatusCode()).isEqualTo(HttpStatus.OK);
    }

    @Test
    void successfulLoginsStillConsumeResourceBudget() {
        RegisterRequest register = new RegisterRequest(); register.setEmail("budget@example.com"); register.setPassword("LongPassword123!");
        assertThat(restTemplate.postForEntity(url("/auth/register"), register, Void.class).getStatusCode()).isEqualTo(HttpStatus.CREATED);
        LoginRequest login = new LoginRequest(); login.setEmail(register.getEmail()); login.setPassword(register.getPassword());
        for (int i = 0; i < 5; i++) assertThat(restTemplate.postForEntity(url("/auth/login"), login, String.class).getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(restTemplate.postForEntity(url("/auth/login"), login, String.class).getStatusCode()).isEqualTo(HttpStatus.TOO_MANY_REQUESTS);
    }

    @Test
    void longUserAgentCannotBreakAuditPersistence() {
        LoginRequest login = new LoginRequest(); login.setEmail("absent@example.com"); login.setPassword("wrong");
        var headers = new org.springframework.http.HttpHeaders(); headers.set("User-Agent", "x".repeat(1000));
        assertThat(restTemplate.postForEntity(url("/auth/login"), new org.springframework.http.HttpEntity<>(login, headers), String.class).getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        assertThat(loginAuditLogRepository.count()).isEqualTo(1);
    }

    @Autowired private com.augustopugliano.cypher.service.RefreshTokenService refreshService;
    @Autowired private com.augustopugliano.cypher.service.RateLimitService rateLimitService;
    @org.springframework.test.context.bean.override.mockito.MockitoSpyBean
    private com.augustopugliano.cypher.service.JwtService jwtService;

    @Test
    void concurrentDuplicateRegistrationHasDomainResponses() throws Exception {
        var request = new RegisterRequest(); request.setEmail("duplicate@example.com"); request.setPassword("LongPassword123!");
        var start = new CountDownLatch(1);
        var requests = java.util.stream.IntStream.range(0, 5).mapToObj(i -> CompletableFuture.supplyAsync(() -> {
            try { start.await(); } catch (InterruptedException e) { throw new IllegalStateException(e); }
            return restTemplate.postForEntity(url("/auth/register"), request, String.class).getStatusCode();
        })).toList();
        start.countDown();
        var statuses = new java.util.ArrayList<org.springframework.http.HttpStatusCode>();
        for (var future : requests) statuses.add(future.get(10, TimeUnit.SECONDS));
        assertThat(statuses).containsOnly(HttpStatus.CREATED, HttpStatus.CONFLICT);
        assertThat(statuses.stream().filter(status -> status == HttpStatus.CREATED)).hasSize(1);
        assertThat(userRepository.count()).isEqualTo(1);
    }

    @Test
    void failedSigningDoesNotConsumeRefreshToken() {
        var request = new RegisterRequest(); request.setEmail("rollback@example.com"); request.setPassword("LongPassword123!");
        restTemplate.postForEntity(url("/auth/register"), request, Void.class);
        var user = userRepository.findByEmail(request.getEmail()).orElseThrow();
        var pair = refreshService.generateAndSaveRefreshToken(user);
        org.mockito.Mockito.doThrow(new IllegalStateException("synthetic signer failure")).when(jwtService).generateToken(org.mockito.ArgumentMatchers.any());
        try {
            var refresh = new RefreshRequest(); refresh.setRefresh_token(pair.rawToken());
            assertThat(restTemplate.postForEntity(url("/auth/refresh"), refresh, String.class).getStatusCode().is5xxServerError()).isTrue();
            assertThat(refreshTokenRepository.findById(pair.entity().getId()).orElseThrow().isRevoked()).isFalse();
            assertThat(refreshTokenRepository.count()).isEqualTo(1);
        } finally { org.mockito.Mockito.reset(jwtService); }
        assertThat(refresh(new CountDownLatch(0), pair.rawToken()).getStatusCode()).isEqualTo(HttpStatus.OK);
    }

    @Test
    void repairsCounterWithoutTtlAndCountsConcurrently() throws Exception {
        redisTemplate.opsForValue().set("synthetic:orphan", "2");
        assertThat(rateLimitService.checkAndIncrement("synthetic:", "orphan")).isEqualTo(3);
        assertThat(redisTemplate.getExpire("synthetic:orphan")).isBetween(1L, 300L);
        var start = new CountDownLatch(1);
        var calls = java.util.stream.IntStream.range(0, 32).mapToObj(i -> CompletableFuture.supplyAsync(() -> {
            try { start.await(); } catch (InterruptedException e) { throw new IllegalStateException(e); }
            return rateLimitService.checkAndIncrement("synthetic:", "race");
        })).toList();
        start.countDown(); var values = new java.util.HashSet<Long>();
        for (var call : calls) values.add(call.get(5, TimeUnit.SECONDS));
        assertThat(values).hasSize(32).contains(1L, 32L);
        assertThat(redisTemplate.getExpire("synthetic:race")).isBetween(1L, 300L);
    }

    @Test
    void requestBodiesAreBoundedAndForwardedHeadersCannotBypassIpBudget() {
        var headers = new org.springframework.http.HttpHeaders(); headers.setContentType(org.springframework.http.MediaType.APPLICATION_JSON);
        assertThat(restTemplate.postForEntity(url("/auth/login"), new org.springframework.http.HttpEntity<>("{\"email\":\"" + "a".repeat(20000) + "\"}", headers), String.class).getStatusCode()).isEqualTo(HttpStatus.CONTENT_TOO_LARGE);
        var login = new LoginRequest(); login.setEmail("absent@example.com"); login.setPassword("wrong");
        for (int i = 0; i < 6; i++) {
            headers.set("X-Forwarded-For", "198.51.100." + i); headers.set("Forwarded", "for=198.51.100." + i);
            var response = restTemplate.postForEntity(url("/auth/login"), new org.springframework.http.HttpEntity<>(login, headers), String.class);
            assertThat(response.getStatusCode()).isEqualTo(i < 5 ? HttpStatus.UNAUTHORIZED : HttpStatus.TOO_MANY_REQUESTS);
        }
    }

    @Test
    void realTokenVerifiesWithIndependentSpringNimbusConsumerAndHttpJwks() {
        var headers = new org.springframework.http.HttpHeaders(); headers.setContentType(org.springframework.http.MediaType.APPLICATION_JSON);
        String registration = "{\"email\":\"identity@example.com\",\"password\":\"LongPassword123!\",\"role\":\"ADMIN\",\"id\":\"injected\"}";
        assertThat(restTemplate.postForEntity(url("/auth/register"), new org.springframework.http.HttpEntity<>(registration, headers), String.class).getStatusCode()).isEqualTo(HttpStatus.CREATED);
        var login = new LoginRequest(); login.setEmail("identity@example.com"); login.setPassword("LongPassword123!");
        var response = restTemplate.postForEntity(url("/auth/login"), login, TokenResponse.class);
        assertThat(response.getHeaders().getFirst("Cache-Control")).contains("no-store");
        assertThat(response.getHeaders().getFirst("Set-Cookie")).isNull();
        String token = response.getBody().getAccess_token();
        var decoder = org.springframework.security.oauth2.jwt.NimbusJwtDecoder.withJwkSetUri(url("/.well-known/jwks.json")).build();
        decoder.setJwtValidator(new org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator<>(
                new org.springframework.security.oauth2.jwt.JwtTimestampValidator(java.time.Duration.ofSeconds(30)),
                new org.springframework.security.oauth2.jwt.JwtIssuerValidator("http://localhost:8080"),
                new org.springframework.security.oauth2.jwt.JwtClaimValidator<java.util.List<String>>("aud", aud -> aud != null && aud.contains("keystone-ecosystem")),
                new org.springframework.security.oauth2.jwt.JwtClaimValidator<java.time.Instant>("exp", java.util.Objects::nonNull),
                new org.springframework.security.oauth2.jwt.JwtClaimValidator<java.time.Instant>("iat", java.util.Objects::nonNull),
                new org.springframework.security.oauth2.jwt.JwtClaimValidator<String>("sub", sub -> {
                    try { return sub != null && java.util.UUID.fromString(sub).toString().equals(sub); }
                    catch (IllegalArgumentException e) { return false; }
                })));
        var jwt = decoder.decode(token);
        assertThat(jwt.getSubject()).isEqualTo(userRepository.findByEmail(login.getEmail()).orElseThrow().getId().toString());
        assertThat(jwt.getClaimAsString("role")).isEqualTo("USER");
        for (String claim : java.util.List.of("iss", "aud")) {
            var claims = new java.util.HashMap<String,Object>(jwt.getClaims()); claims.remove("iat"); claims.remove("exp"); claims.put(claim, "foreign");
            String foreign = io.jsonwebtoken.Jwts.builder().header().keyId("cypher-key").and().claims(claims)
                    .issuedAt(java.util.Date.from(java.time.Instant.now())).expiration(java.util.Date.from(java.time.Instant.now().plusSeconds(900)))
                    .signWith(TestKeys.PRIVATE, io.jsonwebtoken.Jwts.SIG.RS256).compact();
            org.assertj.core.api.Assertions.assertThatThrownBy(() -> decoder.decode(foreign)).isInstanceOf(org.springframework.security.oauth2.jwt.JwtValidationException.class);
        }
        headers.setBearerAuth(token);
        var me = restTemplate.exchange(url("/auth/me"), org.springframework.http.HttpMethod.GET, new org.springframework.http.HttpEntity<>(headers), java.util.Map.class);
        assertThat(me.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(me.getBody().keySet()).containsExactlyInAnyOrder("id", "email", "role");
        assertThat(restTemplate.getForEntity(url("/auth/me"), String.class).getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        headers.setBearerAuth("malformed");
        assertThat(restTemplate.exchange(url("/auth/me"), org.springframework.http.HttpMethod.GET, new org.springframework.http.HttpEntity<>(headers), String.class).getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
    }

    @Test
    void publicRoleInjectionStaysUserAndLocalAnalystCanLoginRefreshAndReadMe() {
        var headers = new org.springframework.http.HttpHeaders(); headers.setContentType(org.springframework.http.MediaType.APPLICATION_JSON);
        String registration = "{\"email\":\"analyst@example.com\",\"password\":\"LongPassword123!\",\"role\":\"ANALYST\"}";
        assertThat(restTemplate.postForEntity(url("/auth/register"), new org.springframework.http.HttpEntity<>(registration, headers), String.class).getStatusCode()).isEqualTo(HttpStatus.CREATED);
        var user = userRepository.findByEmail("analyst@example.com").orElseThrow();
        assertThat(user.getRole()).isEqualTo("USER");
        var login = new LoginRequest(); login.setEmail(user.getEmail()); login.setPassword("LongPassword123!");
        for (String role : java.util.List.of("USER", "ANALYST")) {
            user.setRole(role); userRepository.saveAndFlush(user); // Authorized provisioning in this synthetic fixture only.
            var response = restTemplate.postForEntity(url("/auth/login"), login, TokenResponse.class);
            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
            var refresh = new RefreshRequest(); refresh.setRefresh_token(response.getBody().getRefresh_token());
            var rotated = restTemplate.postForEntity(url("/auth/refresh"), refresh, TokenResponse.class);
            assertThat(rotated.getStatusCode()).isEqualTo(HttpStatus.OK);
            headers.setBearerAuth(rotated.getBody().getAccess_token());
            var me = restTemplate.exchange(url("/auth/me"), org.springframework.http.HttpMethod.GET, new org.springframework.http.HttpEntity<>(headers), java.util.Map.class);
            assertThat(me.getStatusCode()).isEqualTo(HttpStatus.OK);
            assertThat(me.getBody().get("role")).isEqualTo(role);
        }
    }

    @Test
    void redisFailureIsClosedAndRecoveryWorks() throws Exception {
        var login = new LoginRequest(); login.setEmail("absent@example.com"); login.setPassword("wrong");
        redis.execInContainer("redis-cli", "CLIENT", "PAUSE", "1800", "ALL");
        long before = System.nanoTime();
        assertThat(restTemplate.postForEntity(url("/auth/login"), login, String.class).getStatusCode()).isEqualTo(HttpStatus.SERVICE_UNAVAILABLE);
        assertThat(java.time.Duration.ofNanos(System.nanoTime()-before)).isLessThan(java.time.Duration.ofSeconds(3));
        // The ephemeral Redis resumes itself; only this fixture is paused.
        Thread.sleep(1000);
        assertThat(restTemplate.postForEntity(url("/auth/login"), login, String.class).getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
    }

    @Test
    void databaseFailureIsClosedAndRecoveryWorks() throws Exception {
        try (var connection = java.sql.DriverManager.getConnection(postgres.getJdbcUrl(), postgres.getUsername(), postgres.getPassword())) {
            connection.setAutoCommit(false);
            connection.createStatement().execute("LOCK TABLE users IN ACCESS EXCLUSIVE MODE");
            var login = new LoginRequest(); login.setEmail("absent@example.com"); login.setPassword("wrong");
            long before = System.nanoTime();
            assertThat(restTemplate.postForEntity(url("/auth/login"), login, String.class).getStatusCode()).isEqualTo(HttpStatus.SERVICE_UNAVAILABLE);
            assertThat(java.time.Duration.ofNanos(System.nanoTime()-before)).isLessThan(java.time.Duration.ofSeconds(4));
            connection.rollback();
        }
        var login = new LoginRequest(); login.setEmail("absent@example.com"); login.setPassword("wrong");
        assertThat(restTemplate.postForEntity(url("/auth/login"), login, String.class).getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
    }

    @Test
    void boundedLoadPreservesDatabaseInvariantsAndRecovers() throws Exception {
        Path output = Path.of("target/security-load.json");
        Process process = new ProcessBuilder("python3", "scripts/security/load.py", "--url", "http://127.0.0.1:" + port,
                "--fixture-pid", Long.toString(ProcessHandle.current().pid()), "--output", output.toString())
                .redirectErrorStream(true).redirectOutput(Path.of("target/security-load-driver.log").toFile()).start();
        if (!process.waitFor(65, TimeUnit.SECONDS)) { process.destroyForcibly(); throw new AssertionError("Load budget exceeded"); }
        assertThat(process.exitValue()).withFailMessage(Files.readString(Path.of("target/security-load-driver.log"))).isZero();
        var jdbc = new org.springframework.jdbc.core.JdbcTemplate(dataSource);
        assertThat(jdbc.queryForObject("SELECT count(*) FROM (SELECT replaced_by FROM refresh_tokens WHERE replaced_by IS NOT NULL GROUP BY replaced_by HAVING count(*) > 1) branches", Long.class)).isZero();
        assertThat(jdbc.queryForObject("SELECT count(*) FROM refresh_tokens old LEFT JOIN refresh_tokens successor ON old.replaced_by = successor.id WHERE old.replaced_by IS NOT NULL AND (NOT old.revoked OR successor.id IS NULL OR old.expires_at <> successor.expires_at)", Long.class)).isZero();
        assertThat(jdbc.queryForObject("SELECT count(*) FROM refresh_tokens WHERE length(token_hash) <> 64", Long.class)).isZero();
        assertThat(jdbc.queryForObject("SELECT count(*) FROM (SELECT email FROM users GROUP BY email HAVING count(*) > 1) duplicates", Long.class)).isZero();
        assertThat(jdbc.queryForObject("SELECT count(*) FROM pg_stat_activity WHERE datname = current_database()", Long.class)).isLessThanOrEqualTo(10);
        assertThat(userRepository.findByEmail("recovery@example.com")).isPresent();
    }

    @Test
    void sustainedAdmittedAuthenticationRecoversAndPreservesPersistence() throws Exception {
        Process process = new ProcessBuilder("python3", "scripts/security/load.py", "--sustained", "--url", "http://127.0.0.1:" + port,
                "--fixture-pid", Long.toString(ProcessHandle.current().pid()), "--output", "target/security-sustained.json")
                .redirectErrorStream(true).redirectOutput(Path.of("target/security-sustained-driver.log").toFile()).start();
        if (!process.waitFor(215, TimeUnit.SECONDS)) { process.destroyForcibly(); throw new AssertionError("Sustained budget exceeded"); }
        assertThat(process.exitValue()).withFailMessage(Files.readString(Path.of("target/security-sustained-driver.log"))).isZero();
        var jdbc = new org.springframework.jdbc.core.JdbcTemplate(dataSource);
        assertThat(userRepository.count()).isEqualTo(61);
        assertThat(loginAuditLogRepository.count()).isEqualTo(121);
        assertThat(refreshTokenRepository.count()).isEqualTo(121);
        assertThat(jdbc.queryForObject("SELECT count(*) FROM refresh_tokens WHERE revoked", Long.class)).isEqualTo(60);
        assertThat(jdbc.queryForObject("SELECT count(*) FROM refresh_tokens old LEFT JOIN refresh_tokens successor ON old.replaced_by = successor.id WHERE (old.revoked AND old.replaced_by IS NULL) OR (old.replaced_by IS NOT NULL AND (NOT old.revoked OR successor.id IS NULL OR old.expires_at <> successor.expires_at))", Long.class)).isZero();
        assertThat(jdbc.queryForObject("SELECT count(*) FROM refresh_tokens WHERE length(token_hash) <> 64", Long.class)).isZero();
        assertThat(jdbc.queryForObject("SELECT count(*) FROM (SELECT replaced_by FROM refresh_tokens WHERE replaced_by IS NOT NULL GROUP BY replaced_by HAVING count(*) > 1) branches", Long.class)).isZero();
        assertThat(jdbc.queryForObject("SELECT count(*) FROM (SELECT email FROM users GROUP BY email HAVING count(*) > 1) duplicates", Long.class)).isZero();
        assertThat(jdbc.queryForObject("SELECT count(*) FROM pg_stat_activity WHERE datname = current_database()", Long.class)).isLessThanOrEqualTo(10);
        assertThat(userRepository.findByEmail("sustained-recovery@example.com")).isPresent();
    }
    @Autowired private javax.sql.DataSource dataSource;

    @Test
    void syntheticDatabaseBackupRestoresAndSchemaReinitializesSafely() throws Exception {
        var request = new RegisterRequest(); request.setEmail("backup@example.com"); request.setPassword("LongPassword123!");
        assertThat(restTemplate.postForEntity(url("/auth/register"), request, Void.class).getStatusCode()).isEqualTo(HttpStatus.CREATED);
        var dump = postgres.execInContainer("sh", "-c", "pg_dump -U test -d cypher_test -Fc -f /tmp/synthetic.dump && createdb -U test restore_test && pg_restore -U test -d restore_test /tmp/synthetic.dump");
        assertThat(dump.getExitCode()).isZero();
        var restored = postgres.execInContainer("psql", "-U", "test", "-d", "restore_test", "-tAc", "SELECT count(*) FROM users WHERE email = 'backup@example.com'");
        assertThat(restored.getExitCode()).isZero(); assertThat(restored.getStdout().trim()).isEqualTo("1");
        try (var connection = dataSource.getConnection()) {
            org.springframework.jdbc.datasource.init.ScriptUtils.executeSqlScript(connection, new org.springframework.core.io.ClassPathResource("schema.sql"));
        }
        assertThat(userRepository.findByEmail(request.getEmail())).isPresent();
    }

    @Test
    void blockedIpCannotPoisonOtherAccountBudgets() {
        var login = new LoginRequest(); login.setEmail("attacker@example.com"); login.setPassword("wrong");
        for (int i = 0; i < 6; i++) restTemplate.postForEntity(url("/auth/login"), login, String.class);
        login.setEmail("victim@example.com");
        assertThat(restTemplate.postForEntity(url("/auth/login"), login, String.class).getStatusCode()).isEqualTo(HttpStatus.TOO_MANY_REQUESTS);
        assertThat(redisTemplate.hasKey("login_account:victim@example.com")).isFalse();
    }

    @Test
    void failedSuccessfulAuditRollsBackLoginSession() {
        var request = new RegisterRequest(); request.setEmail("audit-rollback@example.com"); request.setPassword("LongPassword123!");
        restTemplate.postForEntity(url("/auth/register"), request, Void.class);
        var login = new LoginRequest(); login.setEmail(request.getEmail()); login.setPassword(request.getPassword());
        org.mockito.Mockito.doThrow(new org.springframework.dao.DataAccessResourceFailureException("synthetic audit failure"))
                .when(loginAuditLogRepository).saveAndFlush(org.mockito.ArgumentMatchers.any());
        try {
            assertThat(restTemplate.postForEntity(url("/auth/login"), login, String.class).getStatusCode()).isEqualTo(HttpStatus.SERVICE_UNAVAILABLE);
            assertThat(refreshTokenRepository.count()).isZero(); assertThat(loginAuditLogRepository.count()).isZero();
        } finally { org.mockito.Mockito.reset(loginAuditLogRepository); }
    }

    @Test
    void unknownExpiredAndRevokedRefreshTokensAreRejectedWithoutReplacement() {
        var request = new RefreshRequest(); request.setRefresh_token("a".repeat(43));
        assertThat(restTemplate.postForEntity(url("/auth/refresh"), request, String.class).getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        var register = new RegisterRequest(); register.setEmail("invalid-refresh@example.com"); register.setPassword("LongPassword123!");
        restTemplate.postForEntity(url("/auth/register"), register, String.class);
        var login = new LoginRequest(); login.setEmail(register.getEmail()); login.setPassword(register.getPassword());
        var pair = restTemplate.postForEntity(url("/auth/login"), login, TokenResponse.class).getBody();
        request.setRefresh_token(pair.getRefresh_token());
        var original = refreshTokenRepository.findAll().getFirst();
        original.setExpiresAt(java.time.Instant.now().minusSeconds(1)); refreshTokenRepository.saveAndFlush(original);
        assertThat(restTemplate.postForEntity(url("/auth/refresh"), request, String.class).getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        original.setExpiresAt(java.time.Instant.now().plusSeconds(60)); original.setRevoked(true); refreshTokenRepository.saveAndFlush(original);
        assertThat(restTemplate.postForEntity(url("/auth/refresh"), request, String.class).getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        assertThat(refreshTokenRepository.count()).isEqualTo(1);
        assertThat(refreshTokenRepository.findAll().getFirst().getReplacedBy()).isNull();
    }

    @Test
    void successorDatabaseFailureRollsBackRefreshConsumption() {
        var register = new RegisterRequest(); register.setEmail("refresh-storage@example.com"); register.setPassword("LongPassword123!");
        restTemplate.postForEntity(url("/auth/register"), register, String.class);
        var login = new LoginRequest(); login.setEmail(register.getEmail()); login.setPassword(register.getPassword());
        var pair = restTemplate.postForEntity(url("/auth/login"), login, TokenResponse.class).getBody();
        var original = refreshTokenRepository.findAll().getFirst();
        var jdbc = new org.springframework.jdbc.core.JdbcTemplate(dataSource);
        // Fixture-only constraint forces a real PostgreSQL insert failure after rotation starts.
        jdbc.execute("ALTER TABLE refresh_tokens ADD CONSTRAINT synthetic_no_successor CHECK (id = '"+original.getId()+"')");
        var request = new RefreshRequest(); request.setRefresh_token(pair.getRefresh_token());
        try {
            assertThat(restTemplate.postForEntity(url("/auth/refresh"), request, String.class).getStatusCode()).isEqualTo(HttpStatus.SERVICE_UNAVAILABLE);
            assertThat(refreshTokenRepository.count()).isEqualTo(1);
            var retained = refreshTokenRepository.findAll().getFirst();
            assertThat(retained.isRevoked()).isFalse(); assertThat(retained.getReplacedBy()).isNull();
        } finally { jdbc.execute("ALTER TABLE refresh_tokens DROP CONSTRAINT synthetic_no_successor"); }
        assertThat(restTemplate.postForEntity(url("/auth/refresh"), request, String.class).getStatusCode()).isEqualTo(HttpStatus.OK);
    }

    @Test
    void tricklingBodyHasDeadlineAndChunkedSizeIsBounded() throws Exception {
        try (var socket = new java.net.Socket("127.0.0.1", port)) {
            socket.setSoTimeout(12000);
            socket.getOutputStream().write(("POST /auth/login HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: 100\r\nConnection: close\r\n\r\n").getBytes(java.nio.charset.StandardCharsets.US_ASCII));
            var result = CompletableFuture.supplyAsync(() -> {
                try { return new java.io.BufferedReader(new java.io.InputStreamReader(socket.getInputStream())).readLine(); }
                catch (java.io.IOException e) { throw new IllegalStateException(e); }
            });
            long before = System.nanoTime();
            for (int i = 0; i < 35 && !result.isDone(); i++) {
                socket.getOutputStream().write('x'); socket.getOutputStream().flush(); Thread.sleep(200);
            }
            assertThat(result.get(4, TimeUnit.SECONDS)).contains("408");
            assertThat(java.time.Duration.ofNanos(System.nanoTime()-before)).isLessThan(java.time.Duration.ofSeconds(11));
        }
        try (var socket = new java.net.Socket("127.0.0.1", port)) {
            socket.setSoTimeout(5000);
            var out = socket.getOutputStream();
            out.write("POST /auth/login HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n5000\r\n".getBytes());
            out.write("x".repeat(0x5000).getBytes()); out.write("\r\n0\r\n\r\n".getBytes()); out.flush();
            assertThat(new java.io.BufferedReader(new java.io.InputStreamReader(socket.getInputStream())).readLine()).contains("413");
        }
    }

    @Test
    void applicationRestartRetainsIdentityAndTokenContinuity() throws Exception {
        String[] arguments = {"--server.port=0", "--spring.config.import=", "--logging.level.root=ERROR",
                "--spring.datasource.url="+postgres.getJdbcUrl(), "--spring.datasource.username="+postgres.getUsername(),
                "--spring.datasource.password="+postgres.getPassword(), "--spring.data.redis.host="+redis.getHost(),
                "--spring.data.redis.port="+redis.getFirstMappedPort(), "--cypher.jwt.keystore.location=file:"+TEST_KEYSTORE,
                "--cypher.jwt.keystore.password="+TEST_KEYSTORE_PASSWORD, "--cypher.anthropic.enabled=false",
                "--cypher.geoip.db-path=missing-test-geoip.mmdb", "--spring.sql.init.mode=always"};
        TokenResponse pair;
        try (var first = new org.springframework.boot.builder.SpringApplicationBuilder(CypherApplication.class).run(arguments)) {
            int firstPort = ((org.springframework.boot.web.server.context.WebServerApplicationContext)first).getWebServer().getPort();
            var register = new RegisterRequest(); register.setEmail("restart@example.com"); register.setPassword("LongPassword123!");
            assertThat(restTemplate.postForEntity("http://127.0.0.1:"+firstPort+"/auth/register", register, String.class).getStatusCode()).isEqualTo(HttpStatus.CREATED);
            var login = new LoginRequest(); login.setEmail(register.getEmail()); login.setPassword(register.getPassword());
            pair = restTemplate.postForEntity("http://127.0.0.1:"+firstPort+"/auth/login", login, TokenResponse.class).getBody();
        }
        try (var second = new org.springframework.boot.builder.SpringApplicationBuilder(CypherApplication.class).run(arguments)) {
            int secondPort = ((org.springframework.boot.web.server.context.WebServerApplicationContext)second).getWebServer().getPort();
            var headers = new org.springframework.http.HttpHeaders(); headers.setBearerAuth(pair.getAccess_token());
            assertThat(restTemplate.exchange("http://127.0.0.1:"+secondPort+"/auth/me", org.springframework.http.HttpMethod.GET,
                    new org.springframework.http.HttpEntity<>(headers), String.class).getStatusCode()).isEqualTo(HttpStatus.OK);
            var refresh = new RefreshRequest(); refresh.setRefresh_token(pair.getRefresh_token());
            assertThat(restTemplate.postForEntity("http://127.0.0.1:"+secondPort+"/auth/refresh", refresh, String.class).getStatusCode()).isEqualTo(HttpStatus.OK);
        }
    }

    @Test
    @org.junit.jupiter.api.extension.ExtendWith(org.springframework.boot.test.system.OutputCaptureExtension.class)
    void invalidPasswordIsNotCopiedToLogsOrResponse(org.springframework.boot.test.system.CapturedOutput output) {
        String sensitive = "SyntheticNeverLogPassword".repeat(6);
        var login = new LoginRequest(); login.setEmail("privacy@example.com"); login.setPassword(sensitive);
        var response = restTemplate.postForEntity(url("/auth/login"), login, String.class);
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(response.getBody() == null ? "" : response.getBody()).doesNotContain(sensitive);
        assertThat(output.getAll()).doesNotContain(sensitive);
    }

    @Test
    void boundedMalformedInputCampaignDoesNotReachPersistence() {
        var headers = new org.springframework.http.HttpHeaders(); headers.setContentType(org.springframework.http.MediaType.APPLICATION_JSON);
        for (var body : java.util.List.of("null", "{}", "[]", "{", "{\"email\":null,\"password\":null}", "{\"email\":\"bad\",\"password\":\"x\"}", "{\"email\":\"user@example.com\",\"password\":\""+"x".repeat(129)+"\"}")) {
            assertThat(restTemplate.postForEntity(url("/auth/login"), new org.springframework.http.HttpEntity<>(body,headers), String.class).getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        }
        for (var bearer : java.util.List.of("none", "a.b.c", "x".repeat(4097))) {
            headers.setBearerAuth(bearer);
            assertThat(restTemplate.exchange(url("/auth/me"), org.springframework.http.HttpMethod.GET, new org.springframework.http.HttpEntity<>(headers), String.class).getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        }
        assertThat(userRepository.count()).isZero(); assertThat(loginAuditLogRepository.count()).isZero(); assertThat(refreshTokenRepository.count()).isZero();
    }

    private ResponseEntity<TokenResponse> refresh(CountDownLatch start, String token) {
        try {
            start.await();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException(e);
        }
        RefreshRequest request = new RefreshRequest();
        request.setRefresh_token(token);
        return restTemplate.postForEntity(url("/auth/refresh"), request, TokenResponse.class);
    }

}
