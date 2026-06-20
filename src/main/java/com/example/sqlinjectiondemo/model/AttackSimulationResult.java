package com.example.sqlinjectiondemo.model;

public class AttackSimulationResult {

    private final String username;
    private final String payload;
    private final DetectionResult detectionResult;
    private final AuthResult vulnerableResult;
    private final AuthResult secureResult;

    public AttackSimulationResult(String username, String payload, DetectionResult detectionResult,
                                  AuthResult vulnerableResult, AuthResult secureResult) {
        this.username = username;
        this.payload = payload;
        this.detectionResult = detectionResult;
        this.vulnerableResult = vulnerableResult;
        this.secureResult = secureResult;
    }

    public String getUsername() {
        return username;
    }

    public String getPayload() {
        return payload;
    }

    public DetectionResult getDetectionResult() {
        return detectionResult;
    }

    public AuthResult getVulnerableResult() {
        return vulnerableResult;
    }

    public AuthResult getSecureResult() {
        return secureResult;
    }
}
