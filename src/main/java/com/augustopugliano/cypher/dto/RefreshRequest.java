package com.augustopugliano.cypher.dto;

import jakarta.validation.constraints.NotBlank;

public class RefreshRequest {
    
    @NotBlank
    @jakarta.validation.constraints.Pattern(regexp = "[A-Za-z0-9_-]{43}")
    private String refresh_token;

    public String getRefresh_token() { return refresh_token; }
    public void setRefresh_token(String refresh_token) { this.refresh_token = refresh_token; }
}
