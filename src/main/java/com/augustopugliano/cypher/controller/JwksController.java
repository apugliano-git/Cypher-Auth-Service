package com.augustopugliano.cypher.controller;

import com.augustopugliano.cypher.service.JwtService;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.interfaces.RSAPublicKey;
import java.util.Base64;
import java.util.List;
import java.util.Map;

@RestController
public class JwksController {

    private final JwtService jwtService;

    public JwksController(JwtService jwtService) {
        this.jwtService = jwtService;
    }

    private static String unsigned(java.math.BigInteger integer) {
        byte[] bytes = integer.toByteArray();
        if (bytes.length > 1 && bytes[0] == 0) bytes = java.util.Arrays.copyOfRange(bytes, 1, bytes.length);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    @GetMapping("/.well-known/jwks.json")
    public Map<String, Object> getJwks() {
        RSAPublicKey publicKey = (RSAPublicKey) jwtService.getPublicKey();
        
        String n = unsigned(publicKey.getModulus());
        String e = unsigned(publicKey.getPublicExponent());

        Map<String, Object> key = Map.of(
            "kty", "RSA",
            "kid", jwtService.getKeyId(),
            "use", "sig",
            "alg", "RS256",
            "n", n,
            "e", e
        );

        return Map.of("keys", List.of(key));
    }
}
