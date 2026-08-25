package com.augustopugliano.cypher.security;

public record AuthenticatedUser(String id, String email, String role) {
}
