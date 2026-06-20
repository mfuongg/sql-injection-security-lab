package com.example.sqlinjectiondemo.model;

import java.util.List;

public class DetectionResult {

    private final boolean suspicious;
    private final List<String> matchedKeywords;
    private final int riskScore;
    private final String riskLevel;
    private final String summary;

    public DetectionResult(boolean suspicious, List<String> matchedKeywords, int riskScore,
                           String riskLevel, String summary) {
        this.suspicious = suspicious;
        this.matchedKeywords = matchedKeywords;
        this.riskScore = riskScore;
        this.riskLevel = riskLevel;
        this.summary = summary;
    }

    public boolean isSuspicious() {
        return suspicious;
    }

    public List<String> getMatchedKeywords() {
        return matchedKeywords;
    }

    public int getRiskScore() {
        return riskScore;
    }

    public String getRiskLevel() {
        return riskLevel;
    }

    public String getSummary() {
        return summary;
    }
}
