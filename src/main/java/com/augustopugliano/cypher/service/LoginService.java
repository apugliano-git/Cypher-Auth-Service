package com.augustopugliano.cypher.service;

import com.augustopugliano.cypher.dto.AnomalyResult;
import com.augustopugliano.cypher.dto.LoginRequest;
import com.augustopugliano.cypher.dto.TokenResponse;
import com.augustopugliano.cypher.model.LoginAuditLog;
import com.augustopugliano.cypher.model.User;
import com.augustopugliano.cypher.repository.LoginAuditLogRepository;
import com.augustopugliano.cypher.repository.UserRepository;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import java.util.Optional;

@Service
public class LoginService {

    private final UserRepository userRepository;
    private final JwtService jwtService;
    private final RefreshTokenService refreshTokenService;
    private final PasswordEncoder passwordEncoder;
    private final RateLimitService rateLimitService;
    private final LoginAuditLogRepository loginAuditLogRepository;
    private final AnomalyDetectionService anomalyDetectionService;
    private final LlmExplanationService llmExplanationService;
    private final int maxAttempts;
    private final String dummyPasswordHash;
    private final org.springframework.transaction.support.TransactionTemplate transaction;

    public LoginService(
            UserRepository userRepository,
            JwtService jwtService,
            RefreshTokenService refreshTokenService,
            PasswordEncoder passwordEncoder,
            RateLimitService rateLimitService,
            LoginAuditLogRepository loginAuditLogRepository,
            AnomalyDetectionService anomalyDetectionService,
            LlmExplanationService llmExplanationService,
            @Value("${cypher.rate-limit.max-attempts}") int maxAttempts,
            org.springframework.transaction.PlatformTransactionManager transactionManager) {
        this.transaction = new org.springframework.transaction.support.TransactionTemplate(transactionManager);
        this.userRepository = userRepository;
        this.jwtService = jwtService;
        this.refreshTokenService = refreshTokenService;
        this.passwordEncoder = passwordEncoder;
        this.dummyPasswordHash = passwordEncoder.encode(java.util.UUID.randomUUID().toString());
        this.rateLimitService = rateLimitService;
        this.loginAuditLogRepository = loginAuditLogRepository;
        this.anomalyDetectionService = anomalyDetectionService;
        this.llmExplanationService = llmExplanationService;
        this.maxAttempts = maxAttempts;
    }

    public TokenResponse performLogin(LoginRequest request, String ipAddress, String userAgent) {
        String email = request.getEmail();

        long ipAttempts = rateLimitService.checkAndIncrement("login_ip:", ipAddress);
        if (ipAttempts > maxAttempts) {
            throw new ResponseStatusException(HttpStatus.TOO_MANY_REQUESTS, "Rate limit exceeded");
        }
        long emailAttempts = rateLimitService.checkAndIncrement("login_account:", email);
        if (emailAttempts > maxAttempts) {
            throw new ResponseStatusException(HttpStatus.TOO_MANY_REQUESTS, "Rate limit exceeded");
        }

        Optional<User> optionalUser = userRepository.findByEmail(email);

        LoginAuditLog auditLog = new LoginAuditLog();
        auditLog.setIpAddress(ipAddress);
        auditLog.setUserAgent(userAgent == null ? null : userAgent.substring(0, Math.min(userAgent.length(), 255)).replaceAll("[\\p{Cntrl}]", " "));

        if (optionalUser.isEmpty()) {
            passwordEncoder.matches(request.getPassword(), dummyPasswordHash);
            auditLog.setSuccess(false);
            loginAuditLogRepository.save(auditLog);
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid credentials");
        }

        User user = optionalUser.get();
        auditLog.setUserId(user.getId());

        if (!passwordEncoder.matches(request.getPassword(), user.getPasswordHash())) {
            auditLog.setSuccess(false);
            loginAuditLogRepository.save(auditLog);
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid credentials");
        }

        record Issued(TokenResponse tokens, Long auditId, AnomalyResult anomaly) {}
        Issued issued = transaction.execute(status -> {
            AnomalyResult anomaly = anomalyDetectionService.evaluate(user.getId(), ipAddress);
            String accessToken = jwtService.generateToken(user);
            RefreshTokenService.TokenPair pair = refreshTokenService.generateAndSaveRefreshToken(user);
            auditLog.setSuccess(true);
            auditLog.setAnomalyFlag(anomaly.isAnomaly());
            LoginAuditLog savedAudit = loginAuditLogRepository.saveAndFlush(auditLog);
            return new Issued(new TokenResponse(accessToken, pair.rawToken(), jwtService.getExpirationSeconds()), savedAudit.getId(), anomaly);
        });
        if (issued.anomaly().isAnomaly()) {
            try {
                llmExplanationService.explainAnomalyAsync(issued.auditId(), issued.anomaly());
            } catch (org.springframework.core.task.TaskRejectedException e) {
                org.slf4j.LoggerFactory.getLogger(LoginService.class).warn("Optional explanation queue is full");
            }
        }
        return issued.tokens();
    }
}
