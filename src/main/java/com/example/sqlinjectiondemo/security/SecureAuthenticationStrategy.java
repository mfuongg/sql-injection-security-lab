package com.example.sqlinjectiondemo.security;

import com.example.sqlinjectiondemo.entity.User;
import com.example.sqlinjectiondemo.model.AuthResult;
import com.example.sqlinjectiondemo.repository.UserRepository;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.util.Optional;

@Component
public class SecureAuthenticationStrategy implements AuthenticationStrategy {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    public SecureAuthenticationStrategy(UserRepository userRepository, PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public String getMode() {
        return "SECURE";
    }

    @Override
    public AuthResult authenticate(String username, String password) {
        String queryPreview = "SELECT * FROM users WHERE username = ?";
        Optional<User> optionalUser = userRepository.findByUsername(username);

        if (optionalUser.isEmpty()) {
            return AuthResult.failed(queryPreview, "Tên đăng nhập hoặc mật khẩu không chính xác.", getMode());
        }

        User user = optionalUser.get();
        if (!user.isEnabled()) {
            return AuthResult.blocked(queryPreview, "Tài khoản đang bị vô hiệu hóa.", getMode());
        }

        if (passwordEncoder.matches(password, user.getPasswordHash())) {
            return AuthResult.success(user, queryPreview,
                    "Xác thực thành công với truy vấn tham số hóa và BCrypt.",
                    getMode());
        }

        return AuthResult.failed(queryPreview,
                "Tên đăng nhập hoặc mật khẩu không chính xác.",
                getMode());
    }
}
