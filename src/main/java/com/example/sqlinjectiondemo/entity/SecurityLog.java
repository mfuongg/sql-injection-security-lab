package com.example.sqlinjectiondemo.entity;

import jakarta.persistence.*;

import java.time.LocalDateTime;

@Entity
@Table(name = "security_logs")
public class SecurityLog {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "event_time", nullable = false)
    private LocalDateTime eventTime;

    @Column(name = "ip_address", nullable = false)
    private String ipAddress;

    @Column(name = "username_input", length = 150)
    private String usernameInput;

    @Column(name = "password_input", length = 300)
    private String passwordInput;

    @Column(length = 500)
    private String payload;

    @Column(name = "login_mode", nullable = false, length = 50)
    private String loginMode;

    @Column(nullable = false, length = 50)
    private String status;

    @Column(nullable = false)
    private boolean suspicious;

    @Column(name = "risk_level", length = 30)
    private String riskLevel;

    @Column(name = "risk_score")
    private Integer riskScore;

    @Column(name = "detector_result", length = 1000)
    private String detectorResult;

    @Column(length = 1500)
    private String message;

    @Column(name = "query_preview", length = 2000)
    private String queryPreview;

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public LocalDateTime getEventTime() {
        return eventTime;
    }

    public void setEventTime(LocalDateTime eventTime) {
        this.eventTime = eventTime;
    }

    public String getIpAddress() {
        return ipAddress;
    }

    public void setIpAddress(String ipAddress) {
        this.ipAddress = ipAddress;
    }

    public String getUsernameInput() {
        return usernameInput;
    }

    public void setUsernameInput(String usernameInput) {
        this.usernameInput = usernameInput;
    }

    public String getPasswordInput() {
        return passwordInput;
    }

    public void setPasswordInput(String passwordInput) {
        this.passwordInput = passwordInput;
    }

    public String getPayload() {
        return payload;
    }

    public void setPayload(String payload) {
        this.payload = payload;
    }

    public String getLoginMode() {
        return loginMode;
    }

    public void setLoginMode(String loginMode) {
        this.loginMode = loginMode;
    }

    public String getStatus() {
        return status;
    }

    public void setStatus(String status) {
        this.status = status;
    }

    public boolean isSuspicious() {
        return suspicious;
    }

    public void setSuspicious(boolean suspicious) {
        this.suspicious = suspicious;
    }

    public String getRiskLevel() {
        return riskLevel;
    }

    public void setRiskLevel(String riskLevel) {
        this.riskLevel = riskLevel;
    }

    public Integer getRiskScore() {
        return riskScore;
    }

    public void setRiskScore(Integer riskScore) {
        this.riskScore = riskScore;
    }

    public String getDetectorResult() {
        return detectorResult;
    }

    public void setDetectorResult(String detectorResult) {
        this.detectorResult = detectorResult;
    }

    public String getMessage() {
        return message;
    }

    public void setMessage(String message) {
        this.message = message;
    }

    public String getQueryPreview() {
        return queryPreview;
    }

    public void setQueryPreview(String queryPreview) {
        this.queryPreview = queryPreview;
    }
}
