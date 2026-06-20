package com.example.sqlinjectiondemo.service;

import com.example.sqlinjectiondemo.entity.SecurityLog;
import com.example.sqlinjectiondemo.model.AuthResult;
import com.example.sqlinjectiondemo.model.DashboardStats;
import com.example.sqlinjectiondemo.model.DetectionResult;
import com.example.sqlinjectiondemo.repository.SecurityLogRepository;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.LocalDateTime;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;

@Service
public class SecurityLogService {

    private final SecurityLogRepository securityLogRepository;

    public SecurityLogService(SecurityLogRepository securityLogRepository) {
        this.securityLogRepository = securityLogRepository;
    }

    public void save(String ipAddress, String username, String password, String loginMode,
                     AuthResult authResult, DetectionResult detectionResult) {
        SecurityLog log = new SecurityLog();
        log.setEventTime(LocalDateTime.now());
        log.setIpAddress(ipAddress);
        log.setUsernameInput(username);
        log.setPasswordInput(maskSensitiveInput(password, detectionResult));
        log.setPayload(buildPayload(username, password, detectionResult));
        log.setLoginMode(loginMode);
        log.setStatus(authResult.getStatus());
        log.setSuspicious(detectionResult.isSuspicious());
        log.setRiskLevel(detectionResult.getRiskLevel());
        log.setRiskScore(detectionResult.getRiskScore());
        log.setDetectorResult(detectionResult.getSummary());
        log.setMessage(sanitizeSecurityMessage(authResult.getMessage(), authResult.getStatus()));
        log.setQueryPreview(authResult.getQueryPreview());
        securityLogRepository.save(log);
    }

    public void saveWorkbenchEvent(String ipAddress, String username, String action,
                                   String payload, int riskScore, String summary, String message) {
        SecurityLog log = new SecurityLog();
        log.setEventTime(LocalDateTime.now());
        log.setIpAddress(normalize(ipAddress));
        log.setUsernameInput(normalize(username));
        log.setPasswordInput(maskWorkbenchPayload(payload));
        log.setPayload(maskWorkbenchPayload(payload));
        log.setLoginMode(normalize(action));
        log.setStatus("SUCCESS");
        log.setSuspicious(riskScore >= 30);
        log.setRiskLevel(mapRiskLevel(riskScore));
        log.setRiskScore(Math.max(0, Math.min(riskScore, 100)));
        log.setDetectorResult(truncate(summary, 220));
        log.setMessage(truncate(message, 220));
        log.setQueryPreview("Security Workbench");
        securityLogRepository.save(log);
    }

    private String buildPayload(String username, String password, DetectionResult detectionResult) {
        return "username=" + normalize(username) + " | password=" + maskSensitiveInput(password, detectionResult);
    }

    private String maskSensitiveInput(String password, DetectionResult detectionResult) {
        if (password == null || password.isBlank()) {
            return "(trống)";
        }
        if (detectionResult != null && detectionResult.isSuspicious()) {
            return "[redacted suspicious input · sha256=" + fingerprint(password) + "]";
        }
        return "********";
    }

    private String maskWorkbenchPayload(String payload) {
        if (payload == null || payload.isBlank()) {
            return "N/A";
        }
        return truncate(payload, 120) + " · sha256=" + fingerprint(payload);
    }

    private String sanitizeSecurityMessage(String rawMessage, String status) {
        String normalized = normalize(rawMessage);
        String lower = normalized.toLowerCase(Locale.ROOT);
        if (lower.contains("sql") || lower.contains("syntax") || lower.contains("constraint")
                || lower.contains("exception") || lower.contains("duplicate entry")) {
            if ("SUCCESS".equalsIgnoreCase(status)) {
                return "Luồng vulnerable cho thấy dấu hiệu truy cập trái phép cần ưu tiên xử lý.";
            }
            return "Đầu vào nguy hiểm đã bị ghi nhận và không phản hồi chi tiết kỹ thuật ra giao diện.";
        }
        return truncate(normalized, 180);
    }

    private String mapRiskLevel(int riskScore) {
        if (riskScore >= 85) {
            return "CRITICAL";
        }
        if (riskScore >= 60) {
            return "HIGH";
        }
        if (riskScore >= 30) {
            return "MEDIUM";
        }
        return "LOW";
    }

    private String fingerprint(String value) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(normalize(value).getBytes(StandardCharsets.UTF_8));
            StringBuilder builder = new StringBuilder();
            for (int i = 0; i < 6 && i < hash.length; i++) {
                builder.append(String.format("%02x", hash[i]));
            }
            return builder.toString();
        } catch (Exception ex) {
            return "unavailable";
        }
    }

    private String truncate(String value, int maxLength) {
        String normalized = normalize(value);
        if (normalized.length() <= maxLength) {
            return normalized;
        }
        return normalized.substring(0, Math.max(0, maxLength - 3)) + "...";
    }

    private String normalize(String value) {
        if (value == null || value.isBlank()) {
            return "N/A";
        }
        return value.replaceAll("\\s+", " ").trim();
    }

    public List<SecurityLog> findAll() {
        return securityLogRepository.findAll().stream()
                .sorted(Comparator.comparing(SecurityLog::getEventTime).reversed())
                .toList();
    }

    public List<SecurityLog> findRecentSuspicious(int limit) {
        return findAll().stream()
                .filter(SecurityLog::isSuspicious)
                .limit(limit)
                .toList();
    }

    public List<SecurityLog> findRecentHighRisk(int limit) {
        return findAll().stream()
                .filter(log -> {
                    String level = log.getRiskLevel() == null ? "" : log.getRiskLevel().toUpperCase(Locale.ROOT);
                    return "HIGH".equals(level) || "CRITICAL".equals(level);
                })
                .limit(limit)
                .toList();
    }

    public List<SecurityLog> findRecentByUsername(String username, int limit) {
        return findAll().stream()
                .filter(log -> log.getUsernameInput() != null && log.getUsernameInput().equalsIgnoreCase(username))
                .limit(limit)
                .toList();
    }

    public long countByUsername(String username) {
        return findAll().stream()
                .filter(log -> log.getUsernameInput() != null && log.getUsernameInput().equalsIgnoreCase(username))
                .count();
    }

    public long countSuspiciousByUsername(String username) {
        return findAll().stream()
                .filter(log -> log.getUsernameInput() != null && log.getUsernameInput().equalsIgnoreCase(username))
                .filter(SecurityLog::isSuspicious)
                .count();
    }

    public long countByUsernameAndStatus(String username, String status) {
        return findAll().stream()
                .filter(log -> log.getUsernameInput() != null && log.getUsernameInput().equalsIgnoreCase(username))
                .filter(log -> log.getStatus() != null && log.getStatus().equalsIgnoreCase(status))
                .count();
    }

    public long countByUsernameAndMode(String username, String mode) {
        return findAll().stream()
                .filter(log -> log.getUsernameInput() != null && log.getUsernameInput().equalsIgnoreCase(username))
                .filter(log -> log.getLoginMode() != null && log.getLoginMode().equalsIgnoreCase(mode))
                .count();
    }

    public long countByRiskLevel(String riskLevel) {
        return findAll().stream()
                .filter(log -> log.getRiskLevel() != null && log.getRiskLevel().equalsIgnoreCase(riskLevel))
                .count();
    }

    public int calculateSystemSecurityScore() {
        DashboardStats stats = buildStats();
        if (stats.getTotalLogs() == 0) {
            return 92;
        }
        double suspiciousRate = (double) stats.getSuspiciousCount() / stats.getTotalLogs();
        double vulnerableRate = (double) stats.getVulnerableSuccessCount() / stats.getTotalLogs();
        double blockedRate = (double) stats.getBlockedCount() / stats.getTotalLogs();
        int score = 100;
        score -= (int) Math.round(suspiciousRate * 35);
        score -= (int) Math.round(vulnerableRate * 30);
        score += (int) Math.round(blockedRate * 10);
        score -= Math.min((int) stats.getFailedCount(), 12);
        return Math.max(35, Math.min(score, 100));
    }

    public int calculateUserTrustScore(String username) {
        long suspicious = countSuspiciousByUsername(username);
        long failed = countByUsernameAndStatus(username, "FAILED");
        long blocked = countByUsernameAndStatus(username, "BLOCKED");
        int score = 100 - (int) suspicious * 14 - (int) failed * 9 - (int) blocked * 18;
        return Math.max(30, Math.min(score, 100));
    }

    public DashboardStats buildStats() {
        List<SecurityLog> logs = findAll();
        long total = logs.size();
        long success = logs.stream().filter(log -> "SUCCESS".equalsIgnoreCase(log.getStatus())).count();
        long failed = logs.stream().filter(log -> "FAILED".equalsIgnoreCase(log.getStatus())).count();
        long blocked = logs.stream().filter(log -> "BLOCKED".equalsIgnoreCase(log.getStatus())).count();
        long suspicious = logs.stream().filter(SecurityLog::isSuspicious).count();
        long vulnerableSuccess = logs.stream()
                .filter(log -> "VULNERABLE".equalsIgnoreCase(log.getLoginMode()))
                .filter(log -> "SUCCESS".equalsIgnoreCase(log.getStatus()))
                .count();
        long secureFailed = logs.stream()
                .filter(log -> "SECURE".equalsIgnoreCase(log.getLoginMode()))
                .filter(log -> "FAILED".equalsIgnoreCase(log.getStatus()) || "BLOCKED".equalsIgnoreCase(log.getStatus()))
                .count();
        return new DashboardStats(total, success, failed, blocked, suspicious, vulnerableSuccess, secureFailed);
    }
}
