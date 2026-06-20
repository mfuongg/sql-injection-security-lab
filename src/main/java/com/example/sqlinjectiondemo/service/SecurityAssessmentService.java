package com.example.sqlinjectiondemo.service;

import com.example.sqlinjectiondemo.model.SecurityTestCaseItem;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class SecurityAssessmentService {

    public List<SecurityTestCaseItem> getRecommendedTestCases() {
        return List.of(
                new SecurityTestCaseItem(
                        "TC-01",
                        "Phát hiện payload bypass cổ điển",
                        "Đánh giá detector có nhận ra mẫu Boolean-based SQL injection hay không.",
                        "Đăng nhập với password: ' OR '1'='1",
                        "Detector gắn cờ suspicious, tăng risk score và ghi lại summary trong nhật ký kiểm toán.",
                        15,
                        "Phát hiện đầu vào"
                ),
                new SecurityTestCaseItem(
                        "TC-02",
                        "So sánh vulnerable và secure",
                        "Chứng minh cùng một payload có thể làm sai lệch truy vấn ở vulnerable nhưng bị vô hiệu hóa ở secure.",
                        "Phòng lab tấn công với username=admin và payload Boolean/Comment-based",
                        "Vulnerable có thể SUCCESS hoặc sai lệch logic; secure phải FAILED hoặc BLOCKED và giữ nguyên cấu trúc truy vấn.",
                        20,
                        "An toàn truy vấn"
                ),
                new SecurityTestCaseItem(
                        "TC-03",
                        "Đăng nhập thành công với tài khoản mới",
                        "Xác minh luồng thêm user không phá vỡ xác thực secure sau khi tạo tài khoản mới.",
                        "Tạo tài khoản mới ở /users rồi đăng nhập bằng secure mode",
                        "Đăng nhập thành công, dashboard render bình thường, không phát sinh lỗi template 500.",
                        10,
                        "Vòng đời xác thực"
                ),
                new SecurityTestCaseItem(
                        "TC-04",
                        "Khóa tài khoản sau nhiều lần sai",
                        "Đánh giá cơ chế giảm brute-force bằng khóa tạm thời tài khoản.",
                        "Nhập sai mật khẩu 5 lần liên tiếp với cùng username",
                        "Tài khoản chuyển sang trạng thái BLOCKED, lockedUntil được cập nhật và người dùng bị từ chối truy cập trong thời gian khóa.",
                        15,
                        "Bảo vệ thông tin xác thực"
                ),
                new SecurityTestCaseItem(
                        "TC-05",
                        "Kiểm tra phân quyền ADMIN và USER",
                        "Đảm bảo tài khoản USER không truy cập được các trang quản trị.",
                        "Đăng nhập USER rồi truy cập /users, /logs, /attack-lab, /defense-matrix",
                        "Hệ thống redirect về dashboard cá nhân; không lộ chức năng quản trị.",
                        15,
                        "Phân quyền theo vai trò"
                ),
                new SecurityTestCaseItem(
                        "TC-06",
                        "Xác minh nhật ký kiểm toán",
                        "Kiểm tra log có đủ thông tin phục vụ đối soát và hậu kiểm.",
                        "Thực hiện cả đăng nhập thành công, thất bại và payload nghi ngờ",
                        "Log lưu được thời gian, IP, username, mode, risk score, detector summary và status.",
                        10,
                        "Kiểm toán và giám sát"
                ),
                new SecurityTestCaseItem(
                        "TC-07",
                        "Kiểm tra HTTP security headers",
                        "Đảm bảo lớp hardening phản hồi các header phòng thủ cơ bản.",
                        "Gửi request bất kỳ tới ứng dụng và quan sát response headers",
                        "Xuất hiện CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy và Permissions-Policy.",
                        10,
                        "Hardening hệ thống"
                ),
                new SecurityTestCaseItem(
                        "TC-08",
                        "Xuất PDF báo cáo kiểm thử",
                        "Đánh giá khả năng tổng hợp minh chứng để nộp và chấm đồ án.",
                        "Từ Ma trận phòng thủ bấm xuất báo cáo PDF",
                        "Sinh ra PDF tiếng Việt đúng phông, có thống kê hệ thống, sự kiện rủi ro và bộ test cases.",
                        5,
                        "Báo cáo minh chứng"
                )
        );
    }

    public int getTotalPoints() {
        return getRecommendedTestCases().stream()
                .mapToInt(SecurityTestCaseItem::getPoints)
                .sum();
    }
}
