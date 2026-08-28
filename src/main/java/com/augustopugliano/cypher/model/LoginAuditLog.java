package com.augustopugliano.cypher.model;

import jakarta.persistence.*;
import java.time.LocalDateTime;
import java.util.UUID;

@Entity
@Table(name = "login_audit_log", indexes = {
    @Index(name = "idx_login_audit_user_success_time", columnList = "user_id, success, created_at")
})
public class LoginAuditLog {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "user_id")
    private UUID userId;

    @Column(name = "ip_address", nullable = false)
    private String ipAddress;

    @Column(name = "user_agent")
    private String userAgent;

    @Column(nullable = false)
    private boolean success;

    @Column(name = "anomaly_flag")
    private Boolean anomalyFlag;

    @Column(name = "anomaly_explanation")
    private String anomalyExplanation;

    @Column(name = "created_at", nullable = false, updatable = false)
    private LocalDateTime createdAt = LocalDateTime.now();

    // Getters and Setters

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public UUID getUserId() {
        return userId;
    }

    public void setUserId(UUID userId) {
        this.userId = userId;
    }

    public String getIpAddress() {
        return ipAddress;
    }

    public void setIpAddress(String ipAddress) {
        this.ipAddress = ipAddress;
    }

    public String getUserAgent() {
        return userAgent;
    }

    public void setUserAgent(String userAgent) {
        this.userAgent = userAgent;
    }

    public boolean isSuccess() {
        return success;
    }

    public void setSuccess(boolean success) {
        this.success = success;
    }

    public Boolean getAnomalyFlag() {
        return anomalyFlag;
    }

    public void setAnomalyFlag(Boolean anomalyFlag) {
        this.anomalyFlag = anomalyFlag;
    }

    public String getAnomalyExplanation() {
        return anomalyExplanation;
    }

    public void setAnomalyExplanation(String anomalyExplanation) {
        this.anomalyExplanation = anomalyExplanation;
    }

    public LocalDateTime getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(LocalDateTime createdAt) {
        this.createdAt = createdAt;
    }
}
