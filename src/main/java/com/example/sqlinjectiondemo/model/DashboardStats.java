package com.example.sqlinjectiondemo.model;

public class DashboardStats {

    private final long totalLogs;
    private final long successCount;
    private final long failedCount;
    private final long blockedCount;
    private final long suspiciousCount;
    private final long vulnerableSuccessCount;
    private final long secureFailedCount;

    public DashboardStats(long totalLogs, long successCount, long failedCount, long blockedCount,
                          long suspiciousCount, long vulnerableSuccessCount, long secureFailedCount) {
        this.totalLogs = totalLogs;
        this.successCount = successCount;
        this.failedCount = failedCount;
        this.blockedCount = blockedCount;
        this.suspiciousCount = suspiciousCount;
        this.vulnerableSuccessCount = vulnerableSuccessCount;
        this.secureFailedCount = secureFailedCount;
    }

    public long getTotalLogs() {
        return totalLogs;
    }

    public long getSuccessCount() {
        return successCount;
    }

    public long getFailedCount() {
        return failedCount;
    }

    public long getBlockedCount() {
        return blockedCount;
    }

    public long getSuspiciousCount() {
        return suspiciousCount;
    }

    public long getVulnerableSuccessCount() {
        return vulnerableSuccessCount;
    }

    public long getSecureFailedCount() {
        return secureFailedCount;
    }
}
