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

    public LoginService(
            UserRepository userRepository,
            JwtService jwtService,
            RefreshTokenService refreshTokenService,
            PasswordEncoder passwordEncoder,
            RateLimitService rateLimitService,
            LoginAuditLogRepository loginAuditLogRepository,
            AnomalyDetectionService anomalyDetectionService,
            LlmExplanationService llmExplanationService,
            @Value("${cypher.rate-limit.max-attempts}") int maxAttempts) {
        this.userRepository = userRepository;
        this.jwtService = jwtService;
        this.refreshTokenService = refreshTokenService;
        this.passwordEncoder = passwordEncoder;
        this.rateLimitService = rateLimitService;
        this.loginAuditLogRepository = loginAuditLogRepository;
        this.anomalyDetectionService = anomalyDetectionService;
        this.llmExplanationService = llmExplanationService;
        this.maxAttempts = maxAttempts;
    }

    public TokenResponse performLogin(LoginRequest request, String ipAddress, String userAgent) {
        String email = request.getEmail();

        long ipAttempts = rateLimitService.checkAndIncrement(ipAddress);
        long emailAttempts = rateLimitService.checkAndIncrement(email);

        if (ipAttempts > maxAttempts || emailAttempts > maxAttempts) {
            throw new ResponseStatusException(HttpStatus.TOO_MANY_REQUESTS, "Rate limit exceeded");
        }

        Optional<User> optionalUser = userRepository.findByEmail(email);

        LoginAuditLog auditLog = new LoginAuditLog();
        auditLog.setIpAddress(ipAddress);
        auditLog.setUserAgent(userAgent);

        if (optionalUser.isEmpty()) {
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

        auditLog.setSuccess(true);
        
        AnomalyResult anomaly = anomalyDetectionService.evaluate(user.getId(), ipAddress);
        if (anomaly.isAnomaly()) {
            auditLog.setAnomalyFlag(true);
        } else {
            auditLog.setAnomalyFlag(false);
        }

        LoginAuditLog savedAudit = loginAuditLogRepository.save(auditLog);
        
        if (anomaly.isAnomaly()) {
            // TODO: If performLogin is annotated with @Transactional in the future, the @Async call
            // could cause a race condition where the LLM attempts to read the audit log ID before
            // the transaction commits to the DB. In that case, refactor using 
            // ApplicationEventPublisher and @TransactionalEventListener(phase = TransactionPhase.AFTER_COMMIT).
            llmExplanationService.explainAnomalyAsync(savedAudit.getId(), anomaly);
        }

        rateLimitService.reset(ipAddress);
        rateLimitService.reset(email);

        String accessToken = jwtService.generateToken(user);
        RefreshTokenService.TokenPair pair = refreshTokenService.generateAndSaveRefreshToken(user);
        
        return new TokenResponse(accessToken, pair.rawToken(), jwtService.getExpirationSeconds());
    }
}
