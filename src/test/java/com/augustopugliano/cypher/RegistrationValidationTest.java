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

    private RegisterRequest requestWithPassword(String password) {
        RegisterRequest request = new RegisterRequest();
        request.setEmail("user@example.com");
        request.setPassword(password);
        return request;
    }
}
