package com.augustopugliano.cypher.controller;

import org.springframework.web.bind.annotation.*;
import org.springframework.http.*;

@RestControllerAdvice
public class DependencyErrorHandler {
    @ExceptionHandler({org.springframework.web.bind.MethodArgumentNotValidException.class,
            org.springframework.http.converter.HttpMessageNotReadableException.class})
    public ResponseEntity<Void> invalidRequest() {
        // Default MVC validation warnings include rejected values, including passwords.
        return ResponseEntity.badRequest().build();
    }

    @ExceptionHandler({org.springframework.dao.DataAccessException.class,
            org.springframework.transaction.TransactionException.class})
    public ResponseEntity<Void> unavailable(RuntimeException exception) {
        org.slf4j.LoggerFactory.getLogger(DependencyErrorHandler.class).warn("Authentication dependency unavailable: {}", exception.getClass().getSimpleName());
        return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE).build();
    }
}
