package com.augustopugliano.cypher;

import com.augustopugliano.cypher.dto.RegisterRequest;
import jakarta.validation.Validation;
import jakarta.validation.Validator;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class RegistrationValidationTest {

    private final Validator validator = Validation.buildDefaultValidatorFactory().getValidator();

    @Test
    void rejectsPasswordsOutsideTheAllowedLength() {
        assertThat(validator.validate(requestWithPassword("12345678901"))).isNotEmpty();
        assertThat(validator.validate(requestWithPassword("a".repeat(129)))).isNotEmpty();
    }

    @Test
    void boundsLoginAndRefreshWithoutImposingNewPasswordMinimum() {
        var login = new com.augustopugliano.cypher.dto.LoginRequest();
        login.setEmail("user@example.com"); login.setPassword("x");
        assertThat(validator.validate(login)).isEmpty();
        login.setPassword("x".repeat(129));
        assertThat(validator.validate(login)).isNotEmpty();
        var refresh = new com.augustopugliano.cypher.dto.RefreshRequest();
        refresh.setRefresh_token("x".repeat(10000));
        assertThat(validator.validate(refresh)).isNotEmpty();
    }

    @Test
    void acceptsBoundaryAndUnicodePasswordsButRejectsMissingFields() {
        for (var password : java.util.List.of("a".repeat(12), "a".repeat(128), "Clave-🔑-Segura123!")) {
            assertThat(validator.validate(requestWithPassword(password))).isEmpty();
        }
        for (var password : new String[]{null, "", " ".repeat(12)}) {
            assertThat(validator.validate(requestWithPassword(password))).isNotEmpty();
        }
        var request = requestWithPassword("LongPassword123!"); request.setEmail("a".repeat(256)+"@example.com");
        assertThat(validator.validate(request)).isNotEmpty();
    }

    private RegisterRequest requestWithPassword(String password) {
        RegisterRequest request = new RegisterRequest();
        request.setEmail("user@example.com");
        request.setPassword(password);
        return request;
    }
}
