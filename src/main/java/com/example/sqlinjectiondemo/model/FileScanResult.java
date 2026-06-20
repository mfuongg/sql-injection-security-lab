package com.example.sqlinjectiondemo.model;

import java.util.List;

public class FileScanResult {

    private final String fileName;
    private final String mimeType;
    private final long sizeBytes;
    private final String sha256;
    private final String md5;
    private final String riskLevel;
    private final int riskScore;
    private final String summary;
    private final List<SecurityFinding> findings;

    public FileScanResult(String fileName, String mimeType, long sizeBytes, String sha256, String md5,
                          String riskLevel, int riskScore, String summary, List<SecurityFinding> findings) {
        this.fileName = fileName;
        this.mimeType = mimeType;
        this.sizeBytes = sizeBytes;
        this.sha256 = sha256;
        this.md5 = md5;
        this.riskLevel = riskLevel;
        this.riskScore = riskScore;
        this.summary = summary;
        this.findings = findings;
    }

    public String getFileName() {
        return fileName;
    }

    public String getMimeType() {
        return mimeType;
    }

    public long getSizeBytes() {
        return sizeBytes;
    }

    public String getSha256() {
        return sha256;
    }

    public String getMd5() {
        return md5;
    }

    public String getRiskLevel() {
        return riskLevel;
    }

    public int getRiskScore() {
        return riskScore;
    }

    public String getSummary() {
        return summary;
    }

    public List<SecurityFinding> getFindings() {
        return findings;
    }
}
