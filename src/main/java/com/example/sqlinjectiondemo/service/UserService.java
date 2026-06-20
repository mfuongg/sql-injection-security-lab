package com.example.sqlinjectiondemo.service;

import com.example.sqlinjectiondemo.entity.User;
import com.example.sqlinjectiondemo.repository.UserRepository;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.regex.Pattern;

@Service
public class UserService {

    public static final int MAX_FAILED_ATTEMPTS = 5;
    public static final int LOCK_MINUTES = 5;
    private static final Pattern USERNAME_PATTERN = Pattern.compile("^[a-zA-Z0-9._-]{3,32}$");

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    public UserService(UserRepository userRepository, PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }

    public List<User> findAll() {
        return userRepository.findAll().stream()
                .sorted(Comparator.comparing(User::getId, Comparator.nullsLast(Long::compareTo)))
                .toList();
    }

    public Optional<User> findByUsername(String username) {
        return userRepository.findByUsername(normalizeUsername(username));
    }

    public User save(User user) {
        return userRepository.save(user);
    }

    public User createUser(String username, String password, String role) {
        String normalizedUsername = normalizeUsername(username);
        String normalizedRole = normalizeRole(role);
        validateCredentials(normalizedUsername, password);
        if (userRepository.findByUsername(normalizedUsername).isPresent()) {
            throw new IllegalArgumentException("Tên đăng nhập đã tồn tại.");
        }
        User user = new User(normalizedUsername, password, passwordEncoder.encode(password), normalizedRole);
        user.setEnabled(true);
        user.setTwoFactorEnabled(false);
        user.setTwoFactorSecret(null);
        user.setLastTotpCounter(null);
        user.setFailedAttempts(0);
        return userRepository.save(user);
    }

    public User createOrUpdateLabUser(String username, String password, String role) {
        String normalizedUsername = normalizeUsername(username);
        String normalizedRole = normalizeRole(role);
        if (normalizedUsername.isBlank()) {
            throw new IllegalArgumentException("Tên đăng nhập không hợp lệ.");
        }
        if (password == null || password.length() < 6) {
            throw new IllegalArgumentException("Mật khẩu phải có ít nhất 6 ký tự.");
        }
        User user = userRepository.findByUsername(normalizedUsername).orElseGet(User::new);
        user.setUsername(normalizedUsername);
        user.setPassword(password);
        user.setPasswordHash(passwordEncoder.encode(password));
        user.setRole(normalizedRole);
        user.setEnabled(true);
        if (user.getFailedAttempts() < 0) {
            user.setFailedAttempts(0);
        }
        if (user.getTwoFactorSecret() == null) {
            user.setTwoFactorEnabled(false);
            user.setLastTotpCounter(null);
        }
        return userRepository.save(user);
    }

    public User ensureTwoFactorSecret(User user, TwoFactorService twoFactorService) {
        if (user.getTwoFactorSecret() == null || user.getTwoFactorSecret().isBlank()) {
            user.setTwoFactorSecret(twoFactorService.generateSecret());
            user.setTwoFactorEnabled(false);
            user.setLastTotpCounter(null);
            return userRepository.save(user);
        }
        return user;
    }

    public User rotateTwoFactorSecret(User user, TwoFactorService twoFactorService) {
        user.setTwoFactorSecret(twoFactorService.generateSecret());
        user.setTwoFactorEnabled(false);
        user.setLastTotpCounter(null);
        return userRepository.save(user);
    }

    public User enableTwoFactor(User user) {
        user.setTwoFactorEnabled(true);
        return userRepository.save(user);
    }

    public User disableTwoFactor(User user) {
        user.setTwoFactorEnabled(false);
        user.setLastTotpCounter(null);
        return userRepository.save(user);
    }

    public User recordTotpSuccess(User user, long matchedCounter) {
        user.setLastTotpCounter(matchedCounter);
        return userRepository.save(user);
    }

    public boolean isLocked(User user) {
        if (user.getLockedUntil() == null) {
            return false;
        }
        if (user.getLockedUntil().isBefore(LocalDateTime.now())) {
            user.setLockedUntil(null);
            user.setFailedAttempts(0);
            userRepository.save(user);
            return false;
        }
        return true;
    }

    public void recordFailure(String username) {
        userRepository.findByUsername(normalizeUsername(username)).ifPresent(user -> {
            int attempts = user.getFailedAttempts() + 1;
            user.setFailedAttempts(attempts);
            if (attempts >= MAX_FAILED_ATTEMPTS) {
                user.setLockedUntil(LocalDateTime.now().plusMinutes(LOCK_MINUTES));
            }
            userRepository.save(user);
        });
    }

    public void recordSuccess(User user) {
        user.setFailedAttempts(0);
        user.setLockedUntil(null);
        userRepository.save(user);
    }

    private void validateCredentials(String username, String password) {
        if (!USERNAME_PATTERN.matcher(username).matches()) {
            throw new IllegalArgumentException("Tên đăng nhập chỉ được chứa chữ cái, số, dấu chấm, gạch dưới hoặc gạch ngang (3-32 ký tự).");
        }
        if (password == null || password.length() < 6) {
            throw new IllegalArgumentException("Mật khẩu phải có ít nhất 6 ký tự.");
        }
    }

    private String normalizeUsername(String username) {
        return username == null ? "" : username.trim().toLowerCase(Locale.ROOT);
    }

    private String normalizeRole(String role) {
        String normalizedRole = role == null ? "USER" : role.trim().toUpperCase(Locale.ROOT);
        if (!"ADMIN".equals(normalizedRole) && !"USER".equals(normalizedRole)) {
            throw new IllegalArgumentException("Vai trò không hợp lệ.");
        }
        return normalizedRole;
    }
}
