package com.augustopugliano.cypher;

import com.augustopugliano.cypher.dto.LoginRequest;
import com.augustopugliano.cypher.dto.RegisterRequest;
import com.augustopugliano.cypher.dto.RefreshRequest;
import com.augustopugliano.cypher.dto.TokenResponse;
import com.augustopugliano.cypher.model.User;
import com.augustopugliano.cypher.repository.UserRepository;
import com.redis.testcontainers.RedisContainer;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.http.ResponseEntity;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;

import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@Testcontainers
public class AuthIntegrationTest {

    @Container
    static PostgreSQLContainer<?> postgres = new PostgreSQLContainer<>("postgres:16")
            .withDatabaseName("cypher_test")
            .withUsername("test")
            .withPassword("test");

    @Container
    static RedisContainer redis = new RedisContainer(DockerImageName.parse("redis:7"));

    @DynamicPropertySource
    static void configureProperties(DynamicPropertyRegistry registry) {
        registry.add("spring.datasource.url", postgres::getJdbcUrl);
        registry.add("spring.datasource.username", postgres::getUsername);
        registry.add("spring.datasource.password", postgres::getPassword);
        registry.add("spring.data.redis.host", redis::getHost);
        registry.add("spring.data.redis.port", redis::getFirstMappedPort);
        registry.add("cypher.jwt.keystore.location", () -> "file:" + System.getenv("KEYSTORE_PATH"));
        registry.add("cypher.jwt.keystore.password", () -> System.getenv("KEYSTORE_PASSWORD"));
        registry.add("cypher.geoip.db-path", () -> System.getenv("GEOIP_DB_PATH"));
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

    @Autowired
    private com.augustopugliano.cypher.repository.LoginAuditLogRepository loginAuditLogRepository;

    @Autowired
    private org.springframework.data.redis.core.StringRedisTemplate redisTemplate;

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

    @Test
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
        CompletableFuture<ResponseEntity<TokenResponse>> first = CompletableFuture.supplyAsync(() -> refresh(start, refreshToken));
        CompletableFuture<ResponseEntity<TokenResponse>> second = CompletableFuture.supplyAsync(() -> refresh(start, refreshToken));
        start.countDown();

        ResponseEntity<TokenResponse> firstResponse = first.get(10, TimeUnit.SECONDS);
        ResponseEntity<TokenResponse> secondResponse = second.get(10, TimeUnit.SECONDS);
        assertThat(firstResponse.getStatusCode().is2xxSuccessful() ^ secondResponse.getStatusCode().is2xxSuccessful()).isTrue();
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
