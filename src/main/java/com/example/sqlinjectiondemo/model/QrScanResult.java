package com.example.sqlinjectiondemo.model;

import java.util.List;

public class QrScanResult {

    private final String fileName;
    private final String decodedText;
    private final String payloadType;
    private final String riskLevel;
    private final int riskScore;
    private final String summary;
    private final List<SecurityFinding> findings;

    public QrScanResult(String fileName, String decodedText, String payloadType, String riskLevel,
                        int riskScore, String summary, List<SecurityFinding> findings) {
        this.fileName = fileName;
        this.decodedText = decodedText;
        this.payloadType = payloadType;
        this.riskLevel = riskLevel;
        this.riskScore = riskScore;
        this.summary = summary;
        this.findings = findings;
    }

    public String getFileName() {
        return fileName;
    }

    public String getDecodedText() {
        return decodedText;
    }

    public String getPayloadType() {
        return payloadType;
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
