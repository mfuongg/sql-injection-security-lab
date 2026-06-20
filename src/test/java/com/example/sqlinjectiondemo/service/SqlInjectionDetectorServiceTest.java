package com.example.sqlinjectiondemo.service;

import com.example.sqlinjectiondemo.model.DetectionResult;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class SqlInjectionDetectorServiceTest {

    private final SqlInjectionDetectorService detectorService = new SqlInjectionDetectorService();

    @Test
    void shouldFlagClassicBooleanBypassPayload() {
        DetectionResult result = detectorService.inspect("admin", "' or 1=1 --");

        assertTrue(result.isSuspicious());
        assertTrue(result.getRiskScore() >= 30);
        assertNotEquals("LOW", result.getRiskLevel());
    }

    @Test
    void shouldKeepNormalCredentialAsLowRisk() {
        DetectionResult result = detectorService.inspect("student01", "123456");

        assertFalse(result.isSuspicious());
        assertEquals("LOW", result.getRiskLevel());
    }
}
