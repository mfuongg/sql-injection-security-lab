package com.example.sqlinjectiondemo.controller;

import com.example.sqlinjectiondemo.model.AttackSimulationResult;
import com.example.sqlinjectiondemo.service.AttackPayloadService;
import com.example.sqlinjectiondemo.service.AuthService;
import com.example.sqlinjectiondemo.service.SecurityLogService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

@Controller
public class AttackLabController {

    private final AttackPayloadService attackPayloadService;
    private final AuthService authService;
    private final SecurityLogService securityLogService;

    public AttackLabController(AttackPayloadService attackPayloadService,
                               AuthService authService,
                               SecurityLogService securityLogService) {
        this.attackPayloadService = attackPayloadService;
        this.authService = authService;
        this.securityLogService = securityLogService;
    }

    @GetMapping("/attack-lab")
    public String attackLab(Model model, HttpSession session) {
        if (!isAdmin(session)) {
            return "redirect:/dashboard";
        }
        populateCommon(model);
        return "attack-lab";
    }

    @PostMapping("/attack-lab/simulate")
    public String simulate(@RequestParam String username,
                           @RequestParam String payload,
                           Model model,
                           HttpSession session,
                           HttpServletRequest request) {
        if (!isAdmin(session)) {
            return "redirect:/dashboard";
        }
        populateCommon(model);
        AttackSimulationResult result = authService.simulateAttack(username, payload);
        String ipAddress = request.getRemoteAddr() == null ? "127.0.0.1" : request.getRemoteAddr();
        securityLogService.save(ipAddress, username, payload, "VULNERABLE", result.getVulnerableResult(), result.getDetectionResult());
        securityLogService.save(ipAddress, username, payload, "SECURE", result.getSecureResult(), result.getDetectionResult());
        model.addAttribute("simulation", result);
        model.addAttribute("prefillUsername", username);
        model.addAttribute("prefillPayload", payload);
        return "attack-lab";
    }

    private void populateCommon(Model model) {
        model.addAttribute("payloads", attackPayloadService.findAll());
        model.addAttribute("prefillUsername", "admin");
        model.addAttribute("prefillPayload", "' OR '1'='1");
    }

    private boolean isAdmin(HttpSession session) {
        return session.getAttribute("currentUser") != null
                && "ADMIN".equals(session.getAttribute("currentRole"));
    }
}
