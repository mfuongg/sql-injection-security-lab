package com.example.sqlinjectiondemo.model;

public class TwoFactorVerificationResult {

    private final boolean valid;
    private final long matchedCounter;

    public TwoFactorVerificationResult(boolean valid, long matchedCounter) {
        this.valid = valid;
        this.matchedCounter = matchedCounter;
    }

    public boolean isValid() {
        return valid;
    }

    public long getMatchedCounter() {
        return matchedCounter;
    }
}
