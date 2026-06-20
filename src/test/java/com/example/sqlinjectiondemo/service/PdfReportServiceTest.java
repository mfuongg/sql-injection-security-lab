package com.example.sqlinjectiondemo.service;

import com.example.sqlinjectiondemo.entity.SecurityLog;
import com.example.sqlinjectiondemo.model.DashboardStats;
import com.example.sqlinjectiondemo.model.SecurityTestCaseItem;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.time.LocalDateTime;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertTrue;

class PdfReportServiceTest {

    private final PdfReportService pdfReportService = new PdfReportService();

    @Test
    void buildSecurityTestReportShouldGeneratePdfBytes() {
        SecurityLog log = buildSampleLog();
        SecurityTestCaseItem item = new SecurityTestCaseItem(
                "TC-01",
                "Kiểm thử đăng nhập secure",
                "Không lộ lỗi SQL",
                "Sai mật khẩu hoặc payload thử nghiệm",
                "Chỉ trả về thông báo ngắn gọn",
                10,
                "Authentication"
        );

        byte[] pdf = pdfReportService.buildSecurityTestReport(
                new DashboardStats(10, 5, 3, 2, 4, 1, 4),
                91,
                List.of(log),
                List.of(item),
                100
        );

        String content = new String(pdf, StandardCharsets.ISO_8859_1);
        assertTrue(pdf.length > 1000);
        assertTrue(new String(pdf, 0, 4, StandardCharsets.ISO_8859_1).startsWith("%PDF"));
        assertTrue(content.contains("DejaVu") || content.contains("Liberation"));
    }

    @Test
    void buildAuditTrailReportShouldGeneratePdfBytes() {
        SecurityLog log = buildSampleLog();

        byte[] pdf = pdfReportService.buildAuditTrailReport(
                new DashboardStats(10, 5, 3, 2, 4, 1, 4),
                List.of(log),
                List.of(log)
        );

        String content = new String(pdf, StandardCharsets.ISO_8859_1);
        assertTrue(pdf.length > 1000);
        assertTrue(new String(pdf, 0, 4, StandardCharsets.ISO_8859_1).startsWith("%PDF"));
        assertTrue(content.contains("DejaVu") || content.contains("Liberation"));
    }

    private SecurityLog buildSampleLog() {
        SecurityLog log = new SecurityLog();
        log.setEventTime(LocalDateTime.now());
        log.setIpAddress("127.0.0.1");
        log.setUsernameInput("admin");
        log.setLoginMode("SECURE");
        log.setRiskLevel("HIGH");
        log.setRiskScore(82);
        log.setStatus("FAILED");
        log.setDetectorResult("Rủi ro HIGH · phát hiện payload đáng ngờ.");
        log.setMessage("Đầu vào nguy hiểm đã bị ghi nhận và không phản hồi chi tiết kỹ thuật ra giao diện.");
        return log;
    }
}
