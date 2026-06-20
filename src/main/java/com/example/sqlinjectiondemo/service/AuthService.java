package com.example.sqlinjectiondemo.service;

import com.example.sqlinjectiondemo.entity.User;
import com.example.sqlinjectiondemo.model.AttackSimulationResult;
import com.example.sqlinjectiondemo.model.AuthResult;
import com.example.sqlinjectiondemo.model.DetectionResult;
import com.example.sqlinjectiondemo.security.AuthenticationStrategy;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;

@Service
public class AuthService {

    private final Map<String, AuthenticationStrategy> strategies;
    private final UserService userService;
    private final SqlInjectionDetectorService detectorService;

    public AuthService(List<AuthenticationStrategy> strategyList,
                       UserService userService,
                       SqlInjectionDetectorService detectorService) {
        this.strategies = strategyList.stream()
                .collect(Collectors.toMap(strategy -> strategy.getMode().toUpperCase(Locale.ROOT), Function.identity()));
        this.userService = userService;
        this.detectorService = detectorService;
    }

    public AuthResult authenticate(String mode, String username, String password, boolean applyProtection) {
        String normalizedMode = normalizeMode(mode);
        AuthenticationStrategy strategy = strategies.get(normalizedMode);
        if (strategy == null) {
            return AuthResult.failed("N/A", "Chế độ xác thực không hợp lệ.", normalizedMode);
        }

        User inputUser = userService.findByUsername(username).orElse(null);
        if (applyProtection && inputUser != null && userService.isLocked(inputUser)) {
            return AuthResult.blocked("ACCOUNT LOCK CHECK",
                    "Tài khoản bị khóa tạm thời do đăng nhập sai quá nhiều lần. Vui lòng thử lại sau 5 phút.",
                    normalizedMode);
        }

        AuthResult result = strategy.authenticate(username, password);

        if (applyProtection && inputUser != null) {
            if (result.isSuccess()) {
                userService.recordSuccess(inputUser);
            } else if (!result.isBlocked()) {
                userService.recordFailure(username);
            }
        }
        return result;
    }

    public AuthResult vulnerableLogin(String username, String password) {
        return authenticate("VULNERABLE", username, password, true);
    }

    public AuthResult secureLogin(String username, String password) {
        return authenticate("SECURE", username, password, true);
    }

    public AttackSimulationResult simulateAttack(String username, String payload) {
        DetectionResult detectionResult = detectorService.inspect(username, payload);
        AuthResult vulnerable = authenticate("VULNERABLE", username, payload, false);
        AuthResult secure = authenticate("SECURE", username, payload, false);
        return new AttackSimulationResult(username, payload, detectionResult, vulnerable, secure);
    }

    private String normalizeMode(String mode) {
        return mode == null ? "SECURE" : mode.trim().toUpperCase(Locale.ROOT);
    }
}
