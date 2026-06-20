package com.example.sqlinjectiondemo.config;

import com.example.sqlinjectiondemo.entity.AttackPayload;
import com.example.sqlinjectiondemo.entity.SecurityLog;
import com.example.sqlinjectiondemo.repository.AttackPayloadRepository;
import com.example.sqlinjectiondemo.repository.SecurityLogRepository;
import com.example.sqlinjectiondemo.service.UserService;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.time.LocalDateTime;
import java.util.List;

@Configuration
public class DataInitializer {

    @Bean
    CommandLineRunner initDemoData(UserService userService,
                                   AttackPayloadRepository attackPayloadRepository,
                                   SecurityLogRepository securityLogRepository) {
        return args -> {
            userService.createOrUpdateLabUser("admin", "123456", "ADMIN");
            userService.createOrUpdateLabUser("user", "123456", "USER");
            userService.createOrUpdateLabUser("manager", "123456", "ADMIN");
            userService.createOrUpdateLabUser("analyst", "123456", "USER");
            userService.createOrUpdateLabUser("auditor", "123456", "USER");
            userService.createOrUpdateLabUser("lecturer", "123456", "ADMIN");

            List<AttackPayload> payloads = List.of(
                    new AttackPayload("Authentication Bypass", "' OR '1'='1", "Boolean-based",
                            "Payload kinh điển nhằm thay đổi điều kiện xác thực.",
                            "Có thể làm sai lệch logic đăng nhập ở chế độ vulnerable.",
                            "Được xem như dữ liệu đầu vào khi dùng truy vấn an toàn."),
                    new AttackPayload("Comment Tail", "' OR '1'='1' -- ", "Comment-based",
                            "Chèn comment để bỏ qua phần cuối của truy vấn.",
                            "Tăng khả năng bypass nếu câu lệnh bị nối chuỗi trực tiếp.",
                            "Không làm thay đổi truy vấn tham số hóa."),
                    new AttackPayload("Union Probe", "' UNION SELECT 1,2,3 -- ", "UNION-based",
                            "Mô phỏng bước do thám cấu trúc truy vấn.",
                            "Có nguy cơ làm lộ số lượng cột hoặc lỗi SQL.",
                            "Không thể được thực thi như mã SQL."),
                    new AttackPayload("Drop Probe", "'; DROP TABLE users; -- ", "Destructive",
                            "Payload phá hoại để minh họa hậu quả của truy vấn không an toàn.",
                            "Có thể gây gián đoạn dữ liệu trong môi trường thiếu kiểm soát.",
                            "Bị vô hiệu khi dùng cơ chế xác thực an toàn."),
                    new AttackPayload("Boolean Blind", "' OR 1=1 #", "Blind SQLi",
                            "Biến thể boolean-based sử dụng ký tự comment #.",
                            "Có thể khiến truy vấn trả về bản ghi đầu tiên hợp lệ.",
                            "Bị đánh dấu là đầu vào có rủi ro."),
                    new AttackPayload("Order By Probe", "' ORDER BY 3 -- ", "Recon",
                            "Thử đo số cột hợp lệ bằng ORDER BY.",
                            "Dùng cho giai đoạn trinh sát cấu trúc truy vấn.",
                            "Không có tác dụng khi dữ liệu được tham số hóa."),
                    new AttackPayload("Stacked Query", "'; UPDATE users SET role='ADMIN' WHERE username='user'; -- ", "Privilege escalation",
                            "Mô phỏng leo thang đặc quyền bằng truy vấn xếp chồng.",
                            "Có thể làm thay đổi dữ liệu nếu hệ thống thực thi trực tiếp.",
                            "Bị vô hiệu trong luồng xác thực an toàn."),
                    new AttackPayload("Time Delay", "' OR SLEEP(3) -- ", "Time-based",
                            "Mô phỏng kỹ thuật time-based blind SQL injection.",
                            "Cho thấy truy vấn có thể bị điều khiển theo thời gian phản hồi.",
                            "Không phát huy tác dụng trong truy vấn tham số hóa.")
            );

            for (AttackPayload payload : payloads) {
                attackPayloadRepository.findByName(payload.getName())
                        .orElseGet(() -> attackPayloadRepository.save(payload));
            }

            if (securityLogRepository.count() == 0) {
                LocalDateTime now = LocalDateTime.now();
                List<SecurityLog> demoLogs = List.of(
                        sampleLog(now.minusHours(9), "10.10.1.12", "admin", "123456", "SECURE", "SUCCESS", false, "LOW", 8,
                                "Phiên hợp lệ", "Đăng nhập quản trị thành công.", "PreparedStatement authentication"),
                        sampleLog(now.minusHours(8), "10.10.1.21", "user", "123456", "SECURE", "SUCCESS", false, "LOW", 5,
                                "Phiên hợp lệ", "Đăng nhập người dùng thành công.", "PreparedStatement authentication"),
                        sampleLog(now.minusHours(7), "10.10.1.25", "user", "' OR '1'='1", "VULNERABLE", "SUCCESS", true, "CRITICAL", 96,
                                "Có dấu hiệu bypass", "Bypass thành công trên chế độ vulnerable.", "String concatenation authentication"),
                        sampleLog(now.minusHours(6), "10.10.1.25", "user", "' OR '1'='1", "SECURE", "FAILED", true, "CRITICAL", 96,
                                "Payload bị đánh dấu nguy hiểm", "Yêu cầu bị từ chối trên chế độ secure.", "PreparedStatement authentication"),
                        sampleLog(now.minusHours(5), "10.10.1.42", "analyst", "wrong-pass", "SECURE", "FAILED", false, "LOW", 12,
                                "Sai thông tin xác thực", "Mật khẩu không chính xác.", "PreparedStatement authentication"),
                        sampleLog(now.minusHours(4), "10.10.1.42", "analyst", "' UNION SELECT 1,2,3 -- ", "SECURE", "FAILED", true, "HIGH", 78,
                                "Mẫu UNION bị phát hiện", "Đầu vào bị đánh giá rủi ro cao.", "PreparedStatement authentication"),
                        sampleLog(now.minusHours(3), "10.10.1.65", "auditor", "' OR 1=1 #", "VULNERABLE", "SUCCESS", true, "HIGH", 81,
                                "Mẫu boolean blind", "Luồng vulnerable cho phép truy cập trái phép.", "String concatenation authentication"),
                        sampleLog(now.minusHours(2), "10.10.1.65", "auditor", "' OR 1=1 #", "SECURE", "FAILED", true, "HIGH", 81,
                                "Mẫu boolean blind", "Hệ thống secure giữ nguyên tính toàn vẹn xác thực.", "PreparedStatement authentication"),
                        sampleLog(now.minusMinutes(90), "10.10.1.78", "manager", "123456", "SECURE", "SUCCESS", false, "LOW", 6,
                                "Phiên hợp lệ", "Quản trị viên phụ đăng nhập thành công.", "PreparedStatement authentication"),
                        sampleLog(now.minusMinutes(60), "10.10.1.90", "lecturer", "'; DROP TABLE users; -- ", "SECURE", "BLOCKED", true, "CRITICAL", 99,
                                "Payload phá hoại bị chặn", "Yêu cầu bị khóa do rủi ro rất cao.", "PreparedStatement authentication"),
                        sampleLog(now.minusMinutes(35), "10.10.1.91", "user", "123456", "VULNERABLE", "SUCCESS", false, "LOW", 4,
                                "Đăng nhập hợp lệ", "Phiên demo vulnerable hợp lệ.", "String concatenation authentication"),
                        sampleLog(now.minusMinutes(10), "10.10.1.91", "user", "' ORDER BY 3 -- ", "SECURE", "FAILED", true, "MEDIUM", 54,
                                "Mẫu trinh sát bị phát hiện", "Hệ thống ghi nhận nỗ lực do thám cấu trúc truy vấn.", "PreparedStatement authentication")
                );
                securityLogRepository.saveAll(demoLogs);
            }
        };
    }

    private SecurityLog sampleLog(LocalDateTime eventTime,
                                  String ipAddress,
                                  String username,
                                  String password,
                                  String mode,
                                  String status,
                                  boolean suspicious,
                                  String riskLevel,
                                  int riskScore,
                                  String detector,
                                  String message,
                                  String queryPreview) {
        SecurityLog log = new SecurityLog();
        log.setEventTime(eventTime);
        log.setIpAddress(ipAddress);
        log.setUsernameInput(username);
        log.setPasswordInput(password);
        log.setPayload("username=" + username + " | password=" + password);
        log.setLoginMode(mode);
        log.setStatus(status);
        log.setSuspicious(suspicious);
        log.setRiskLevel(riskLevel);
        log.setRiskScore(riskScore);
        log.setDetectorResult(detector);
        log.setMessage(message);
        log.setQueryPreview(queryPreview);
        return log;
    }
}
