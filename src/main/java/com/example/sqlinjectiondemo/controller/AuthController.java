package com.example.sqlinjectiondemo.controller;

import com.example.sqlinjectiondemo.entity.User;
import com.example.sqlinjectiondemo.model.AuthResult;
import com.example.sqlinjectiondemo.model.DashboardStats;
import com.example.sqlinjectiondemo.model.DetectionResult;
import com.example.sqlinjectiondemo.service.AuthService;
import com.example.sqlinjectiondemo.service.SecurityLogService;
import com.example.sqlinjectiondemo.service.SqlInjectionDetectorService;
import com.example.sqlinjectiondemo.service.UserService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import java.util.Locale;

@Controller
public class AuthController {

    private final AuthService authService;
    private final SqlInjectionDetectorService detectorService;
    private final SecurityLogService securityLogService;
    private final UserService userService;

    public AuthController(AuthService authService,
                          SqlInjectionDetectorService detectorService,
                          SecurityLogService securityLogService,
                          UserService userService) {
        this.authService = authService;
        this.detectorService = detectorService;
        this.securityLogService = securityLogService;
        this.userService = userService;
    }

    @GetMapping({"/", "/login"})
    public String loginPage(Model model,
                            @RequestParam(value = "error", required = false) String error,
                            @RequestParam(value = "success", required = false) String success,
                            @RequestParam(value = "warning", required = false) String warning,
                            @RequestParam(value = "prefillUsername", required = false) String prefillUsername,
                            @RequestParam(value = "prefillPassword", required = false) String prefillPassword,
                            @RequestParam(value = "prefillMode", required = false) String prefillMode) {
        model.addAttribute("error", error);
        model.addAttribute("success", success);
        model.addAttribute("warning", warning);
        model.addAttribute("prefillUsername", prefillUsername == null ? "admin" : prefillUsername);
        model.addAttribute("prefillPassword", prefillPassword == null ? "" : prefillPassword);
        model.addAttribute("prefillMode", prefillMode == null ? "secure" : prefillMode);
        return "login";
    }

    @PostMapping("/login")
    public String login(@RequestParam String username,
                        @RequestParam String password,
                        @RequestParam String mode,
                        HttpServletRequest request,
                        HttpSession session,
                        RedirectAttributes redirectAttributes) {

        String normalizedUsername = username == null ? "" : username.trim().toLowerCase(Locale.ROOT);
        String normalizedMode = mode == null ? "secure" : mode.trim().toLowerCase(Locale.ROOT);
        DetectionResult detection = detectorService.inspect(normalizedUsername, password);
        AuthResult authResult = authService.authenticate(normalizedMode, normalizedUsername, password, true);
        String ipAddress = request.getRemoteAddr() == null ? "127.0.0.1" : request.getRemoteAddr();

        securityLogService.save(ipAddress, normalizedUsername, password, authResult.getMode(), authResult, detection);

        if (detection.isSuspicious()) {
            redirectAttributes.addAttribute("warning", "Hệ thống ghi nhận đầu vào có mức rủi ro " + detection.getRiskLevel() + ".");
        }

        if (authResult.isSuccess()) {
            User user = authResult.getUser();
            session.setAttribute("currentUser", user.getUsername());
            session.setAttribute("currentRole", user.getRole());
            session.setAttribute("loginMode", authResult.getMode());
            session.setAttribute("queryPreview", authResult.getQueryPreview());
            session.setAttribute("detectorResult", detection.getSummary());
            session.setAttribute("loginMessage", authResult.getMessage());
            redirectAttributes.addAttribute("success", "Đăng nhập thành công.");
            return "redirect:/dashboard";
        }

        redirectAttributes.addAttribute("error", resolveUserFacingError(authResult));
        redirectAttributes.addAttribute("prefillUsername", normalizedUsername);
        redirectAttributes.addAttribute("prefillMode", normalizedMode);
        return "redirect:/";
    }

    @GetMapping("/dashboard")
    public String dashboard(HttpSession session, Model model,
                            @RequestParam(value = "success", required = false) String success) {
        Object currentUser = session.getAttribute("currentUser");
        if (currentUser == null) {
            return "redirect:/";
        }

        String username = currentUser.toString();
        String role = String.valueOf(session.getAttribute("currentRole"));
        boolean admin = "ADMIN".equalsIgnoreCase(role);
        DashboardStats stats = securityLogService.buildStats();
        User account = userService.findByUsername(username).orElse(null);

        model.addAttribute("username", username);
        model.addAttribute("role", role);
        model.addAttribute("admin", admin);
        model.addAttribute("loginMode", session.getAttribute("loginMode"));
        model.addAttribute("detectorResult", session.getAttribute("detectorResult"));
        model.addAttribute("loginMessage", session.getAttribute("loginMessage"));
        model.addAttribute("success", success);
        model.addAttribute("stats", stats);
        model.addAttribute("account", account);
        model.addAttribute("systemScore", securityLogService.calculateSystemSecurityScore());
        model.addAttribute("userTrustScore", securityLogService.calculateUserTrustScore(username));
        model.addAttribute("recentActivities", securityLogService.findRecentByUsername(username, 8));
        model.addAttribute("personalEvents", securityLogService.countByUsername(username));
        model.addAttribute("personalSuspicious", securityLogService.countSuspiciousByUsername(username));
        model.addAttribute("personalSuccess", securityLogService.countByUsernameAndStatus(username, "SUCCESS"));
        model.addAttribute("personalFailed", securityLogService.countByUsernameAndStatus(username, "FAILED"));
        model.addAttribute("personalBlocked", securityLogService.countByUsernameAndStatus(username, "BLOCKED"));
        model.addAttribute("personalSecure", securityLogService.countByUsernameAndMode(username, "SECURE"));
        model.addAttribute("personalVulnerable", securityLogService.countByUsernameAndMode(username, "VULNERABLE"));
        model.addAttribute("adminRecentSuspicious", securityLogService.findRecentSuspicious(8));
        model.addAttribute("highRiskEvents", securityLogService.findRecentHighRisk(6));
        return "dashboard";
    }

    @GetMapping("/logout")
    public String logout(HttpSession session) {
        session.invalidate();
        return "redirect:/";
    }

    private String resolveUserFacingError(AuthResult authResult) {
        if (authResult == null) {
            return "Tên đăng nhập hoặc mật khẩu không chính xác.";
        }
        if ("BLOCKED".equalsIgnoreCase(authResult.getStatus())) {
            return authResult.getMessage();
        }
        if ("N/A".equalsIgnoreCase(authResult.getMode())) {
            return "Chế độ xác thực không hợp lệ.";
        }
        return "Tên đăng nhập hoặc mật khẩu không chính xác.";
    }
}
