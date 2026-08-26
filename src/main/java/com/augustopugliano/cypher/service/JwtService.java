package com.augustopugliano.cypher.service;

import com.augustopugliano.cypher.model.User;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
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

    public JwtService(
            @Value("${cypher.jwt.keystore.location}") Resource keystoreLocation,
            @Value("${cypher.jwt.keystore.password}") String keystorePassword,
            @Value("${cypher.jwt.keystore.alias}") String keystoreAlias,
            @Value("${cypher.jwt.expiration-seconds:900}") int expirationSeconds) throws Exception {
        
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        try (InputStream is = keystoreLocation.getInputStream()) {
            keyStore.load(is, keystorePassword.toCharArray());
        }

        KeyStore.PrivateKeyEntry privateKeyEntry = (KeyStore.PrivateKeyEntry) keyStore.getEntry(
                keystoreAlias, new KeyStore.PasswordProtection(keystorePassword.toCharArray()));

        this.privateKey = privateKeyEntry.getPrivateKey();
        this.publicKey = privateKeyEntry.getCertificate().getPublicKey();
        this.expirationSeconds = expirationSeconds;
    }

    public int getExpirationSeconds() {
        return expirationSeconds;
    }

    public String generateToken(User user) {
        Instant now = Instant.now();
        Instant expiration = now.plus(expirationSeconds, ChronoUnit.SECONDS);

        return Jwts.builder()
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

    public io.jsonwebtoken.Claims getClaims(String token) {
        return Jwts.parser()
                .verifyWith(publicKey)
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }
}
