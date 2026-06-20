package com.example.sqlinjectiondemo.model;

public class SocDashboardSnapshot {

    private final int unifiedThreatScore;
    private final String severity;
    private final int scannerCoverage;
    private final int twoFactorCoverage;
    private final boolean clamAvAvailable;
    private final boolean yaraAvailable;
    private final long suspiciousEvents;
    private final long highRiskEvents;
    private final long blockedEvents;
    private final long fileScanEvents;
    private final long qrScanEvents;
    private final long twoFactorSuccessEvents;
    private final long twoFactorFailedEvents;
    private final long totalUsers;
    private final long twoFactorEnabledUsers;
    private final String recommendation;

    public SocDashboardSnapshot(int unifiedThreatScore, String severity, int scannerCoverage, int twoFactorCoverage,
                                boolean clamAvAvailable, boolean yaraAvailable, long suspiciousEvents,
                                long highRiskEvents, long blockedEvents, long fileScanEvents, long qrScanEvents,
                                long twoFactorSuccessEvents, long twoFactorFailedEvents, long totalUsers,
                                long twoFactorEnabledUsers, String recommendation) {
        this.unifiedThreatScore = unifiedThreatScore;
        this.severity = severity;
        this.scannerCoverage = scannerCoverage;
        this.twoFactorCoverage = twoFactorCoverage;
        this.clamAvAvailable = clamAvAvailable;
        this.yaraAvailable = yaraAvailable;
        this.suspiciousEvents = suspiciousEvents;
        this.highRiskEvents = highRiskEvents;
        this.blockedEvents = blockedEvents;
        this.fileScanEvents = fileScanEvents;
        this.qrScanEvents = qrScanEvents;
        this.twoFactorSuccessEvents = twoFactorSuccessEvents;
        this.twoFactorFailedEvents = twoFactorFailedEvents;
        this.totalUsers = totalUsers;
        this.twoFactorEnabledUsers = twoFactorEnabledUsers;
        this.recommendation = recommendation;
    }

    public int getUnifiedThreatScore() { return unifiedThreatScore; }
    public String getSeverity() { return severity; }
    public int getScannerCoverage() { return scannerCoverage; }
    public int getTwoFactorCoverage() { return twoFactorCoverage; }
    public boolean isClamAvAvailable() { return clamAvAvailable; }
    public boolean isYaraAvailable() { return yaraAvailable; }
    public long getSuspiciousEvents() { return suspiciousEvents; }
    public long getHighRiskEvents() { return highRiskEvents; }
    public long getBlockedEvents() { return blockedEvents; }
    public long getFileScanEvents() { return fileScanEvents; }
    public long getQrScanEvents() { return qrScanEvents; }
    public long getTwoFactorSuccessEvents() { return twoFactorSuccessEvents; }
    public long getTwoFactorFailedEvents() { return twoFactorFailedEvents; }
    public long getTotalUsers() { return totalUsers; }
    public long getTwoFactorEnabledUsers() { return twoFactorEnabledUsers; }
    public String getRecommendation() { return recommendation; }
}
