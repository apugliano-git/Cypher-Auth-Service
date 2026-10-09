package com.augustopugliano.cypher;

import org.junit.jupiter.api.Test;
import static org.assertj.core.api.Assertions.*;

class PasswordPolicyTest {
    @Test void hashesWithNineteenMiBAndAcceptsExistingEncodedParameters() {
        var encoder = new com.augustopugliano.cypher.config.SecurityConfig(null).passwordEncoder();
        String password = "Unicode-🔑-Password123!";
        var encoded = encoder.encode(password);
        assertThat(encoded).startsWith("$argon2id$v=19$m=19456,t=2,p=1$");
        assertThat(encoder.matches(password, encoded)).isTrue();
        assertThat(encoder.matches(password+" ", encoded)).isFalse();
        String legacy = org.springframework.security.crypto.argon2.Argon2PasswordEncoder.defaultsForSpringSecurity_v5_8().encode(password);
        assertThat(encoder.matches(password, legacy)).isTrue();
    }
}
