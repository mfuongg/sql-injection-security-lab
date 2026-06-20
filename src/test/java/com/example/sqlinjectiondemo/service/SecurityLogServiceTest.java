package com.example.sqlinjectiondemo.service;

import com.example.sqlinjectiondemo.entity.SecurityLog;
import com.example.sqlinjectiondemo.model.AuthResult;
import com.example.sqlinjectiondemo.model.DetectionResult;
import com.example.sqlinjectiondemo.repository.SecurityLogRepository;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class SecurityLogServiceTest {

    @Mock
    private SecurityLogRepository securityLogRepository;

    @InjectMocks
    private SecurityLogService securityLogService;

    @Test
    void saveShouldMaskNormalPasswordAndSanitizeDatabaseErrors() {
        AuthResult authResult = AuthResult.failed("SELECT * FROM users WHERE username='student01'", "Duplicate entry 'student01' for key 'users.username'", "VULNERABLE");
        DetectionResult detectionResult = new DetectionResult(false, List.of(), 0, "LOW", "Không có tín hiệu SQL injection rõ ràng.");
        when(securityLogRepository.save(any(SecurityLog.class))).thenAnswer(invocation -> invocation.getArgument(0));

        securityLogService.save("127.0.0.1", "student01", "123456", "VULNERABLE", authResult, detectionResult);

        ArgumentCaptor<SecurityLog> captor = ArgumentCaptor.forClass(SecurityLog.class);
        verify(securityLogRepository).save(captor.capture());
        SecurityLog log = captor.getValue();
        assertEquals("********", log.getPasswordInput());
        assertEquals("Đầu vào nguy hiểm đã bị ghi nhận và không phản hồi chi tiết kỹ thuật ra giao diện.", log.getMessage());
        assertTrue(log.getPayload().contains("password=********"));
    }

    @Test
    void saveShouldRedactSuspiciousPayloadButKeepDeterministicFingerprint() {
        AuthResult authResult = AuthResult.failed("SELECT * FROM users WHERE username='admin'", "Xác thực thất bại trên luồng vulnerable.", "VULNERABLE");
        DetectionResult detectionResult = new DetectionResult(true, List.of("BOOLEAN BYPASS"), 90, "CRITICAL", "Rủi ro CRITICAL.");
        when(securityLogRepository.save(any(SecurityLog.class))).thenAnswer(invocation -> invocation.getArgument(0));

        securityLogService.save("127.0.0.1", "admin", "' OR '1'='1", "VULNERABLE", authResult, detectionResult);

        ArgumentCaptor<SecurityLog> captor = ArgumentCaptor.forClass(SecurityLog.class);
        verify(securityLogRepository).save(captor.capture());
        SecurityLog log = captor.getValue();
        assertTrue(log.getPasswordInput().startsWith("[redacted suspicious input"));
        assertTrue(log.getPayload().contains("sha256="));
    }
}
