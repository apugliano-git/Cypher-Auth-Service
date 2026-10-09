package com.augustopugliano.cypher.service;

import com.augustopugliano.cypher.model.User;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import java.time.Clock;
import java.security.interfaces.RSAPublicKey;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.Resource;
import org.springframework.stereotype.Service;

import java.io.InputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.UUID;

@Service
public class JwtService {

    private final PrivateKey privateKey;
    private final PublicKey publicKey;
    private final int expirationSeconds;
    private final String issuer;
    private final String audience;
    private final String keyId;
    private final Clock clock;

    public JwtService(
            @Value("${cypher.jwt.keystore.location}") Resource keystoreLocation,
            @Value("${cypher.jwt.keystore.password}") String keystorePassword,
            @Value("${cypher.jwt.keystore.alias}") String keystoreAlias,
            @Value("${cypher.jwt.expiration-seconds:900}") int expirationSeconds,
            @Value("${cypher.jwt.issuer:http://localhost:8080}") String issuer,
            @Value("${cypher.jwt.audience:keystone-ecosystem}") String audience,
            @Value("${cypher.jwt.key-id:cypher-key}") String keyId,
            Clock clock) throws Exception {
        
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        try (InputStream is = keystoreLocation.getInputStream()) {
            keyStore.load(is, keystorePassword.toCharArray());
        }

        KeyStore.PrivateKeyEntry privateKeyEntry = (KeyStore.PrivateKeyEntry) keyStore.getEntry(
                keystoreAlias, new KeyStore.PasswordProtection(keystorePassword.toCharArray()));

        if (privateKeyEntry == null || !(privateKeyEntry.getCertificate().getPublicKey() instanceof RSAPublicKey rsa)
                || rsa.getModulus().bitLength() < 2048 || !"RSA".equals(privateKeyEntry.getPrivateKey().getAlgorithm())) {
            throw new IllegalArgumentException("Keystore must contain an RSA private key of at least 2048 bits");
        }
        if (expirationSeconds < 1 || expirationSeconds > 900 || issuer.isBlank() || audience.isBlank() || keyId.isBlank()) {
            throw new IllegalArgumentException("Invalid JWT configuration");
        }
        this.issuer = issuer; this.audience = audience; this.keyId = keyId; this.clock = clock;
        this.privateKey = privateKeyEntry.getPrivateKey();
        this.publicKey = privateKeyEntry.getCertificate().getPublicKey();
        this.expirationSeconds = expirationSeconds;
    }

    public int getExpirationSeconds() {
        return expirationSeconds;
    }

    public String generateToken(User user) {
        if (!allowedRole(user.getRole())) throw new IllegalArgumentException("Unsupported account role");
        Instant now = clock.instant();
        Instant expiration = now.plus(expirationSeconds, ChronoUnit.SECONDS);

        return Jwts.builder()
                .header().keyId(keyId).and()
                .issuer(issuer).audience().add(audience).and()
                .subject(user.getId().toString())
                .claim("email", user.getEmail())
                .claim("role", user.getRole())
                .issuedAt(Date.from(now))
                .expiration(Date.from(expiration))
                .signWith(privateKey, Jwts.SIG.RS256)
                .compact();
    }

    public PublicKey getPublicKey() {
        return publicKey;
    }

    public String getKeyId() { return keyId; }

    private static boolean allowedRole(String role) {
        return "USER".equals(role) || "ANALYST".equals(role);
    }

    public Claims getClaims(String token) {
        if (token == null || token.length() > 4096) throw new JwtException("Invalid token size");
        String[] parts = token.split("\\.", -1);
        if (parts.length != 3 || parts[0].length() > 2048) throw new JwtException("Invalid JWT format");
        try {
            var mapper = tools.jackson.databind.json.JsonMapper.builder()
                    .enable(tools.jackson.core.StreamReadFeature.STRICT_DUPLICATE_DETECTION).build();
            var header = mapper.readValue(java.util.Base64.getUrlDecoder().decode(parts[0]), java.util.Map.class);
            if (!"RS256".equals(header.get("alg")) || !keyId.equals(header.get("kid")) || header.containsKey("zip")) {
                throw new JwtException("Invalid JWT header");
            }
            var raw = mapper.readValue(java.util.Base64.getUrlDecoder().decode(parts[1]), java.util.Map.class);
            for (String name : java.util.List.of("iat", "exp", "nbf")) {
                if ((raw.containsKey(name) || !"nbf".equals(name)) && !(raw.get(name) instanceof Integer || raw.get(name) instanceof Long)) {
                    throw new JwtException("Numeric date required");
                }
            }
        } catch (IllegalArgumentException e) { throw new JwtException("Invalid JWT header", e); }
        var signed = Jwts.parser()
                .verifyWith(publicKey)
                .requireIssuer(issuer).requireAudience(audience)
                .clock(() -> Date.from(clock.instant())).clockSkewSeconds(30)
                .build().parseSignedClaims(token);
        Claims claims = signed.getPayload();
        try {
            if (!keyId.equals(signed.getHeader().getKeyId()) || claims.getSubject() == null
                    || !UUID.fromString(claims.getSubject()).toString().equals(claims.getSubject())
                    || !(claims.get("iat") instanceof Number) || !(claims.get("exp") instanceof Number)
                    || claims.getIssuedAt() == null || claims.getExpiration() == null
                    || claims.getIssuedAt().toInstant().isAfter(clock.instant().plusSeconds(30))
                    || !claims.getExpiration().after(claims.getIssuedAt())
                    || claims.getExpiration().getTime() - claims.getIssuedAt().getTime() > expirationSeconds * 1000L
                    || claims.get("email", String.class) == null || claims.get("email", String.class).isBlank()
                    || claims.get("email", String.class).length() > 255
                    || !allowedRole(claims.get("role", String.class))) {
                throw new JwtException("Invalid identity claims");
            }
            // RFC 7519: reject at the exact expiration + allowed skew boundary.
            if (!clock.instant().minusSeconds(30).isBefore(claims.getExpiration().toInstant())) {
                throw new JwtException("Expired token");
            }
            if (claims.containsKey("nbf") && (!(claims.get("nbf") instanceof Number)
                    || claims.getNotBefore().after(claims.getExpiration()))) throw new JwtException("Invalid nbf");
        } catch (IllegalArgumentException e) {
            throw new JwtException("Invalid identity claims", e);
        }
        return claims;
    }
}
