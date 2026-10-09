package com.augustopugliano.cypher;

import com.augustopugliano.cypher.service.JwtService;
import com.augustopugliano.cypher.controller.JwksController;
import com.augustopugliano.cypher.model.User;
import io.jsonwebtoken.Jwts;
import java.time.Instant;
import java.util.*;
import org.junit.jupiter.api.Test;
import static org.assertj.core.api.Assertions.*;

class JwtContractTest {
    private final JwtService service = new JwtService(TestKeys.resource(), TestKeys.PASSWORD, "cypher-key", 900, "http://localhost:8080", "keystone-ecosystem", "cypher-key", java.time.Clock.systemUTC());
    JwtContractTest() throws Exception {}
    @Test void rejectsSignedTokensMissingContractClaims() {
        String token = Jwts.builder().subject(UUID.randomUUID().toString()).signWith(TestKeys.PRIVATE, Jwts.SIG.RS256).compact();
        assertThatThrownBy(() -> service.getClaims(token)).isInstanceOf(RuntimeException.class);
    }
    @Test void emitsIdentityContract() {
        User user = new User(); user.setId(UUID.randomUUID()); user.setEmail("user@example.com");
        var token = service.generateToken(user);
        var parsed = Jwts.parser().verifyWith(service.getPublicKey()).build().parseSignedClaims(token);
        assertThat(parsed.getHeader().getKeyId()).isEqualTo("cypher-key");
        assertThat(parsed.getPayload().getIssuer()).isEqualTo("http://localhost:8080");
        assertThat(parsed.getPayload().getAudience()).containsExactly("keystone-ecosystem");
    }
    @Test void issuedTokensRoundTripForBothLocallyProvisionedRoles() {
        for (String role : List.of("USER", "ANALYST")) {
            User user = new User(); user.setId(UUID.randomUUID()); user.setEmail("role@example.com"); user.setRole(role);
            assertThat(service.getClaims(service.generateToken(user)).get("role", String.class)).isEqualTo(role);
        }
    }
    @Test void invalidRolesCannotBeIssuedOrAccepted() throws Exception {
        var verifier = fixedService();
        for (String role : Arrays.asList(null, "", "ADMIN", "analyst", "ROLE_ANALYST", "USER,ANALYST")) {
            User user = new User(); user.setId(UUID.randomUUID()); user.setEmail("role@example.com"); user.setRole(role);
            assertThatThrownBy(() -> service.generateToken(user)).as("issue %s", role).isInstanceOf(IllegalArgumentException.class);
            var claims = validClaims(); claims.put("role", role);
            assertThatThrownBy(() -> verifier.getClaims(signed(claims))).as("accept %s", role).isInstanceOf(RuntimeException.class);
        }
    }
    @Test void jwksUsesUnsignedMinimalRsaIntegers() {
        var keys = (List<Map<String,Object>>) new JwksController(service).getJwks().get("keys");
        assertThat(Base64.getUrlDecoder().decode((String)keys.getFirst().get("n"))).hasSize(256);
        assertThat(keys.getFirst().keySet()).containsExactlyInAnyOrder("kty", "kid", "use", "alg", "n", "e");
    }
    private static final Instant NOW = Instant.parse("2026-10-08T12:00:00Z");
    private JwtService fixedService() throws Exception {
        return new JwtService(TestKeys.resource(), TestKeys.PASSWORD, "cypher-key", 900,
                "http://localhost:8080", "keystone-ecosystem", "cypher-key", java.time.Clock.fixed(NOW, java.time.ZoneOffset.UTC));
    }
    private Map<String,Object> validClaims() {
        var claims = new HashMap<String,Object>();
        claims.put("sub", UUID.randomUUID().toString()); claims.put("email", "user@example.com"); claims.put("role", "USER");
        claims.put("iss", "http://localhost:8080"); claims.put("aud", List.of("keystone-ecosystem"));
        claims.put("iat", NOW.minusSeconds(60).getEpochSecond()); claims.put("exp", NOW.plusSeconds(840).getEpochSecond());
        return claims;
    }
    private String signed(Map<String,Object> claims) {
        try {
            var mapper = new tools.jackson.databind.json.JsonMapper();
            var encoder = Base64.getUrlEncoder().withoutPadding();
            String input = encoder.encodeToString(mapper.writeValueAsBytes(Map.of("alg", "RS256", "kid", "cypher-key"))) + "." + encoder.encodeToString(mapper.writeValueAsBytes(claims));
            var signature = java.security.Signature.getInstance("SHA256withRSA"); signature.initSign(TestKeys.PRIVATE);
            signature.update(input.getBytes(java.nio.charset.StandardCharsets.US_ASCII));
            return input + "." + encoder.encodeToString(signature.sign());
        } catch (Exception e) { throw new IllegalStateException(e); }
    }
    @Test void rejectsMissingAndWronglyTypedClaims() throws Exception {
        var verifier = fixedService();
        for (String claim : List.of("iss", "aud", "sub", "iat", "exp", "email", "role")) {
            var absent = validClaims(); absent.remove(claim);
            assertThatThrownBy(() -> verifier.getClaims(signed(absent))).as("missing %s", claim).isInstanceOf(RuntimeException.class);
            var wrong = validClaims(); wrong.put(claim, Map.of("unexpected", true));
            assertThatThrownBy(() -> verifier.getClaims(signed(wrong))).as("wrong type %s", claim).isInstanceOf(RuntimeException.class);
        }
        for (var mutation : List.of(Map.entry("iss", "https://foreign.example"), Map.entry("aud", "wrong"), Map.entry("sub", ""), Map.entry("role", "ADMIN"), Map.entry("email", ""))) {
            var claims = validClaims(); claims.put(mutation.getKey(), mutation.getValue());
            assertThatThrownBy(() -> verifier.getClaims(signed(claims))).isInstanceOf(RuntimeException.class);
        }
    }
    @Test void expirationAndFutureClaimsHaveDeterministicBoundaries() throws Exception {
        var verifier = fixedService(); var claims = validClaims();
        claims.put("exp", NOW.minusSeconds(29).getEpochSecond());
        assertThat(verifier.getClaims(signed(claims))).isNotNull();
        claims.put("exp", NOW.minusSeconds(30).getEpochSecond());
        assertThatThrownBy(() -> verifier.getClaims(signed(claims))).isInstanceOf(RuntimeException.class);
        for (String claim : List.of("iat", "nbf")) {
            var future = validClaims(); future.put(claim, NOW.plusSeconds(31).getEpochSecond());
            assertThatThrownBy(() -> verifier.getClaims(signed(future))).isInstanceOf(RuntimeException.class);
        }
    }
    @Test void rejectsUnsignedAlteredWrongKeyAlgorithmsAndMalformedTokens() throws Exception {
        var verifier = fixedService(); var good = signed(validClaims());
        var otherKey = java.security.KeyPairGenerator.getInstance("RSA"); otherKey.initialize(2048);
        var wrong = Jwts.builder().claims(validClaims()).signWith(otherKey.generateKeyPair().getPrivate(), Jwts.SIG.RS256).compact();
        var rs512 = Jwts.builder().claims(validClaims()).signWith(TestKeys.PRIVATE, Jwts.SIG.RS512).compact();
        var none = Jwts.builder().claims(validClaims()).compact();
        for (var invalid : List.of(wrong, rs512, none, "malformed", "a".repeat(5000), good.substring(0, good.lastIndexOf('.')+1)+"invalid")) {
            assertThatThrownBy(() -> verifier.getClaims(invalid)).isInstanceOf(RuntimeException.class);
        }
        var unknownKid = Jwts.builder().header().keyId("foreign").and().claims(validClaims()).signWith(TestKeys.PRIVATE, Jwts.SIG.RS256).compact();
        assertThatThrownBy(() -> verifier.getClaims(unknownKid)).isInstanceOf(RuntimeException.class);
    }
    @Test void tokenUrlsCannotSelectTrustedKeys() throws Exception {
        var token = Jwts.builder().header().keyId("cypher-key").add("jku", "http://127.0.0.1:1/untrusted").add("x5u", "http://127.0.0.1:1/untrusted").and()
                .claims(validClaims()).signWith(TestKeys.PRIVATE, Jwts.SIG.RS256).compact();
        assertThat(fixedService().getClaims(token).getSubject()).isNotBlank();
    }

    @Test void compressedAndDuplicateHeadersAreRejectedBeforePayloadWork() throws Exception {
        var compressed = Jwts.builder().header().keyId("cypher-key").and().claims(validClaims()).compressWith(Jwts.ZIP.DEF)
                .signWith(TestKeys.PRIVATE, Jwts.SIG.RS256).compact();
        assertThatThrownBy(() -> fixedService().getClaims(compressed)).isInstanceOf(io.jsonwebtoken.JwtException.class);
        String header = Base64.getUrlEncoder().withoutPadding().encodeToString("{\"alg\":\"RS256\",\"alg\":\"none\",\"kid\":\"cypher-key\"}".getBytes());
        assertThatThrownBy(() -> fixedService().getClaims(header+".e30.invalid")).isInstanceOf(RuntimeException.class);
    }

    @Test void numericDateStringsAreNotNumericClaims() throws Exception {
        for (var name : List.of("iat", "exp", "nbf")) {
            var claims = validClaims(); claims.put(name, Long.toString(NOW.getEpochSecond()));
            assertThatThrownBy(() -> fixedService().getClaims(signed(claims))).as(name).isInstanceOf(RuntimeException.class);
        }
    }

    @Test void invalidKeystoreAliasPasswordAndLifetimeFailClosed() {
        assertThatThrownBy(() -> new JwtService(TestKeys.resource(), "synthetic-incorrect", "cypher-key",900,"issuer","audience","kid",java.time.Clock.systemUTC())).isInstanceOf(Exception.class);
        assertThatThrownBy(() -> new JwtService(TestKeys.resource(), TestKeys.PASSWORD,"missing",900,"issuer","audience","kid",java.time.Clock.systemUTC())).isInstanceOf(Exception.class);
        assertThatThrownBy(() -> new JwtService(TestKeys.resource(), TestKeys.PASSWORD,"cypher-key",0,"issuer","audience","kid",java.time.Clock.systemUTC())).isInstanceOf(IllegalArgumentException.class);
    }

}
