package com.augustopugliano.cypher.dto;

public class TokenResponse {
    
    private String access_token;
    private String refresh_token;
    private int expires_in;

    public TokenResponse(String access_token, String refresh_token, int expires_in) {
        this.access_token = access_token;
        this.refresh_token = refresh_token;
        this.expires_in = expires_in;
    }

    public String getAccess_token() { return access_token; }
    public void setAccess_token(String access_token) { this.access_token = access_token; }
    public int getExpires_in() { return expires_in; }
    public void setExpires_in(int expires_in) { this.expires_in = expires_in; }
    public String getRefresh_token() { return refresh_token; }
    public void setRefresh_token(String refresh_token) { this.refresh_token = refresh_token; }
}
