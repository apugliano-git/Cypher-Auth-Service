package com.augustopugliano.cypher.service;

import com.augustopugliano.cypher.model.RefreshToken;
import com.augustopugliano.cypher.model.User;
import com.augustopugliano.cypher.repository.RefreshTokenRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.HexFormat;

@Service
public class RefreshTokenService {

    private final RefreshTokenRepository refreshTokenRepository;
    private final SecureRandom secureRandom;
    private final int refreshExpirationDays;

    public RefreshTokenService(RefreshTokenRepository refreshTokenRepository, 
            @org.springframework.beans.factory.annotation.Value("${cypher.jwt.refresh.expiration-days:7}") int refreshExpirationDays) {
        this.refreshTokenRepository = refreshTokenRepository;
        this.secureRandom = new SecureRandom();
        this.refreshExpirationDays = refreshExpirationDays;
    }

    public record TokenPair(RefreshToken entity, String rawToken) {}
    public record RotationResult(User user, String newRawToken) {}

    @Transactional
    public TokenPair generateAndSaveRefreshToken(User user) {
        byte[] randomBytes = new byte[32];
        secureRandom.nextBytes(randomBytes);
        String rawToken = Base64.getUrlEncoder().withoutPadding().encodeToString(randomBytes);

        String tokenHash = hashToken(rawToken);

        RefreshToken refreshToken = new RefreshToken();
        refreshToken.setUser(user);
        refreshToken.setTokenHash(tokenHash);
        refreshToken.setIssuedAt(Instant.now());
        refreshToken.setExpiresAt(Instant.now().plus(refreshExpirationDays, ChronoUnit.DAYS));
        refreshToken.setRevoked(false);

        refreshTokenRepository.save(refreshToken);

        return new TokenPair(refreshToken, rawToken);
    }

    public String hashToken(String rawToken) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hashBytes = digest.digest(rawToken.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(hashBytes);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256 not available", e);
        }
    }

    @Transactional
    public RotationResult processRefresh(String rawRefreshToken) {
        String tokenHash = hashToken(rawRefreshToken);
        RefreshToken refreshToken = refreshTokenRepository.findByTokenHash(tokenHash)
                .orElseThrow(() -> new com.augustopugliano.cypher.exception.TokenRefreshException("Invalid refresh token"));

        if (refreshToken.isRevoked() || refreshToken.getExpiresAt().isBefore(Instant.now())) {
            throw new com.augustopugliano.cypher.exception.TokenRefreshException("Invalid or expired refresh token");
        }

        refreshToken.setRevoked(true);

        User user = refreshToken.getUser();
        TokenPair newPair = generateAndSaveRefreshToken(user);

        refreshToken.setReplacedBy(newPair.entity().getId());
        refreshTokenRepository.save(refreshToken);

        return new RotationResult(user, newPair.rawToken());
    }
}
