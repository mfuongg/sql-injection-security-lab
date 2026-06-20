package com.example.sqlinjectiondemo.controller;

import com.example.sqlinjectiondemo.entity.User;
import com.example.sqlinjectiondemo.service.PdfReportService;
import com.example.sqlinjectiondemo.service.SecurityAssessmentService;
import com.example.sqlinjectiondemo.service.SecurityLogService;
import com.example.sqlinjectiondemo.service.UserService;
import jakarta.servlet.http.HttpSession;
import org.springframework.http.ContentDisposition;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import java.util.List;

@Controller
public class AdminController {

    private final SecurityLogService securityLogService;
    private final UserService userService;
    private final SecurityAssessmentService securityAssessmentService;
    private final PdfReportService pdfReportService;

    public AdminController(SecurityLogService securityLogService,
                           UserService userService,
                           SecurityAssessmentService securityAssessmentService,
                           PdfReportService pdfReportService) {
        this.securityLogService = securityLogService;
        this.userService = userService;
        this.securityAssessmentService = securityAssessmentService;
        this.pdfReportService = pdfReportService;
    }

    @GetMapping("/logs")
    public String logs(Model model, HttpSession session) {
        if (!isAdmin(session)) {
            return "redirect:/dashboard";
        }
        model.addAttribute("logs", securityLogService.findAll());
        model.addAttribute("stats", securityLogService.buildStats());
        model.addAttribute("highRiskEvents", securityLogService.findRecentHighRisk(6));
        return "logs";
    }

    @GetMapping("/monitor")
    public String monitor(HttpSession session) {
        if (!isAdmin(session)) {
            return "redirect:/dashboard";
        }
        return "redirect:/logs";
    }

    @GetMapping("/defense-matrix")
    public String defenseMatrix(Model model, HttpSession session) {
        if (!isAdmin(session)) {
            return "redirect:/dashboard";
        }
        model.addAttribute("stats", securityLogService.buildStats());
        model.addAttribute("systemScore", securityLogService.calculateSystemSecurityScore());
        model.addAttribute("criticalCount", securityLogService.countByRiskLevel("CRITICAL"));
        model.addAttribute("highCount", securityLogService.countByRiskLevel("HIGH"));
        model.addAttribute("mediumCount", securityLogService.countByRiskLevel("MEDIUM"));
        model.addAttribute("lowCount", securityLogService.countByRiskLevel("LOW"));
        model.addAttribute("highRiskEvents", securityLogService.findRecentHighRisk(6));
        model.addAttribute("testCases", securityAssessmentService.getRecommendedTestCases());
        model.addAttribute("totalTestPoints", securityAssessmentService.getTotalPoints());
        return "defense-matrix";
    }

    @GetMapping(value = "/reports/security-test.pdf", produces = MediaType.APPLICATION_PDF_VALUE)
    public ResponseEntity<byte[]> securityTestReport(HttpSession session) {
        if (!isAdmin(session)) {
            return ResponseEntity.status(302)
                    .header(HttpHeaders.LOCATION, "/dashboard")
                    .build();
        }

        byte[] pdf = pdfReportService.buildSecurityTestReport(
                securityLogService.buildStats(),
                securityLogService.calculateSystemSecurityScore(),
                securityLogService.findRecentHighRisk(8),
                securityAssessmentService.getRecommendedTestCases(),
                securityAssessmentService.getTotalPoints()
        );

        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_DISPOSITION, ContentDisposition.attachment()
                        .filename("bao-cao-kiem-thu-bao-mat.pdf")
                        .build()
                        .toString())
                .contentType(MediaType.APPLICATION_PDF)
                .body(pdf);
    }

    @GetMapping(value = "/reports/audit-trail.pdf", produces = MediaType.APPLICATION_PDF_VALUE)
    public ResponseEntity<byte[]> auditTrailReport(HttpSession session) {
        if (!isAdmin(session)) {
            return ResponseEntity.status(302)
                    .header(HttpHeaders.LOCATION, "/dashboard")
                    .build();
        }

        byte[] pdf = pdfReportService.buildAuditTrailReport(
                securityLogService.buildStats(),
                securityLogService.findAll(),
                securityLogService.findRecentHighRisk(10)
        );

        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_DISPOSITION, ContentDisposition.attachment()
                        .filename("audit-trail-bao-mat.pdf")
                        .build()
                        .toString())
                .contentType(MediaType.APPLICATION_PDF)
                .body(pdf);
    }

    @GetMapping("/users")
    public String users(Model model, HttpSession session,
                        @RequestParam(value = "message", required = false) String message,
                        @RequestParam(value = "error", required = false) String error) {
        if (!isAdmin(session)) {
            return "redirect:/dashboard";
        }
        List<User> users = userService.findAll();
        long adminCount = users.stream().filter(user -> "ADMIN".equalsIgnoreCase(user.getRole())).count();
        long userCount = users.stream().filter(user -> "USER".equalsIgnoreCase(user.getRole())).count();
        long activeCount = users.stream().filter(User::isEnabled).count();
        long lockedCount = users.stream().filter(User::isLocked).count();

        model.addAttribute("users", users);
        model.addAttribute("adminCount", adminCount);
        model.addAttribute("userCount", userCount);
        model.addAttribute("activeCount", activeCount);
        model.addAttribute("lockedCount", lockedCount);
        model.addAttribute("message", message);
        model.addAttribute("error", error);
        return "users";
    }

    @PostMapping("/users/add")
    public String addUser(@RequestParam String username,
                          @RequestParam String password,
                          @RequestParam(defaultValue = "USER") String role,
                          RedirectAttributes redirectAttributes,
                          HttpSession session) {
        if (!isAdmin(session)) {
            return "redirect:/dashboard";
        }
        try {
            userService.createUser(username, password, role.toUpperCase());
            redirectAttributes.addAttribute("message", "Tạo tài khoản thành công.");
        } catch (IllegalArgumentException ex) {
            redirectAttributes.addAttribute("error", ex.getMessage());
        } catch (Exception ex) {
            redirectAttributes.addAttribute("error", "Không thể tạo tài khoản. Vui lòng kiểm tra dữ liệu đầu vào.");
        }
        return "redirect:/users";
    }

    private boolean isAdmin(HttpSession session) {
        return session.getAttribute("currentUser") != null
                && "ADMIN".equals(session.getAttribute("currentRole"));
    }
}
