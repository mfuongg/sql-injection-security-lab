package com.example.sqlinjectiondemo.controller;

import com.example.sqlinjectiondemo.model.CryptoLabResult;
import com.example.sqlinjectiondemo.model.FileScanResult;
import com.example.sqlinjectiondemo.model.QrScanResult;
import com.example.sqlinjectiondemo.service.CsrfService;
import com.example.sqlinjectiondemo.service.SecurityLogService;
import com.example.sqlinjectiondemo.service.SecurityWorkbenchService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.multipart.MultipartFile;

@Controller
public class SecurityWorkbenchController {

    private final SecurityWorkbenchService securityWorkbenchService;
    private final SecurityLogService securityLogService;
    private final CsrfService csrfService;

    public SecurityWorkbenchController(SecurityWorkbenchService securityWorkbenchService,
                                       SecurityLogService securityLogService,
                                       CsrfService csrfService) {
        this.securityWorkbenchService = securityWorkbenchService;
        this.securityLogService = securityLogService;
        this.csrfService = csrfService;
    }

    @GetMapping("/security-workbench")
    public String workbench(Model model, HttpSession session) {
        if (!isAdmin(session)) {
            return "redirect:/dashboard";
        }
        populateCommon(model, session);
        return "security-workbench";
    }

    @PostMapping("/security-workbench/file-scan")
    public String fileScan(@RequestParam("file") MultipartFile file,
                           @RequestParam("csrfToken") String csrfToken,
                           HttpSession session,
                           HttpServletRequest request,
                           Model model) {
        if (!isAdmin(session)) {
            return "redirect:/dashboard";
        }
        if (!csrfService.isValid(session, csrfToken)) {
            populateCommon(model, session);
            model.addAttribute("error", "CSRF token không hợp lệ. Vui lòng tải lại trang.");
            return "security-workbench";
        }
        try {
            FileScanResult result = securityWorkbenchService.analyzeFile(file);
            securityLogService.saveWorkbenchEvent(remoteIp(request), currentUser(session), "FILE_SCAN",
                    result.getFileName(), result.getRiskScore(), result.getSummary(), "Workbench file scan");
            populateCommon(model, session);
            model.addAttribute("fileScanResult", result);
        } catch (Exception ex) {
            populateCommon(model, session);
            model.addAttribute("error", ex.getMessage());
        }
        return "security-workbench";
    }

    @PostMapping("/security-workbench/qr-scan")
    public String qrScan(@RequestParam("file") MultipartFile file,
                         @RequestParam("csrfToken") String csrfToken,
                         HttpSession session,
                         HttpServletRequest request,
                         Model model) {
        if (!isAdmin(session)) {
            return "redirect:/dashboard";
        }
        if (!csrfService.isValid(session, csrfToken)) {
            populateCommon(model, session);
            model.addAttribute("error", "CSRF token không hợp lệ. Vui lòng tải lại trang.");
            return "security-workbench";
        }
        try {
            QrScanResult result = securityWorkbenchService.analyzeQr(file);
            securityLogService.saveWorkbenchEvent(remoteIp(request), currentUser(session), "QR_SCAN",
                    result.getFileName(), result.getRiskScore(), result.getSummary(), "Workbench QR scan");
            populateCommon(model, session);
            model.addAttribute("qrScanResult", result);
        } catch (Exception ex) {
            populateCommon(model, session);
            model.addAttribute("error", ex.getMessage());
        }
        return "security-workbench";
    }

    @PostMapping("/security-workbench/crypto")
    public String crypto(@RequestParam("operation") String operation,
                         @RequestParam("inputValue") String inputValue,
                         @RequestParam(value = "secret", required = false) String secret,
                         @RequestParam("csrfToken") String csrfToken,
                         HttpSession session,
                         HttpServletRequest request,
                         Model model) {
        if (!isAdmin(session)) {
            return "redirect:/dashboard";
        }
        if (!csrfService.isValid(session, csrfToken)) {
            populateCommon(model, session);
            model.addAttribute("error", "CSRF token không hợp lệ. Vui lòng tải lại trang.");
            return "security-workbench";
        }
        try {
            CryptoLabResult result = securityWorkbenchService.runCrypto(operation, inputValue, secret);
            securityLogService.saveWorkbenchEvent(remoteIp(request), currentUser(session), "CRYPTO_" + operation,
                    operation, 6, result.getNote(), "Workbench crypto operation");
            populateCommon(model, session);
            model.addAttribute("selectedOperation", operation);
            model.addAttribute("inputValue", inputValue);
            model.addAttribute("cryptoResult", result);
        } catch (Exception ex) {
            populateCommon(model, session);
            model.addAttribute("selectedOperation", operation);
            model.addAttribute("inputValue", inputValue);
            model.addAttribute("error", ex.getMessage());
        }
        return "security-workbench";
    }

    private void populateCommon(Model model, HttpSession session) {
        model.addAttribute("csrfToken", csrfService.ensureToken(session));
        model.addAttribute("selectedOperation", "sha256");
        model.addAttribute("inputValue", "");
    }

    private String remoteIp(HttpServletRequest request) {
        String forwarded = request.getHeader("X-Forwarded-For");
        if (forwarded != null && !forwarded.isBlank()) {
            return forwarded.split(",")[0].trim();
        }
        return request.getRemoteAddr() == null ? "127.0.0.1" : request.getRemoteAddr();
    }

    private String currentUser(HttpSession session) {
        Object currentUser = session.getAttribute("currentUser");
        return currentUser == null ? "admin" : currentUser.toString();
    }

    private boolean isAdmin(HttpSession session) {
        return session.getAttribute("currentUser") != null
                && "ADMIN".equals(session.getAttribute("currentRole"));
    }
}
