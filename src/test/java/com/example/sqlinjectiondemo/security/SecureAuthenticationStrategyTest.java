package com.example.sqlinjectiondemo.security;

import com.example.sqlinjectiondemo.entity.User;
import com.example.sqlinjectiondemo.model.AuthResult;
import com.example.sqlinjectiondemo.repository.UserRepository;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.BDDMockito.given;

@ExtendWith(MockitoExtension.class)
class SecureAuthenticationStrategyTest {

    @Mock
    private UserRepository userRepository;

    @Mock
    private PasswordEncoder passwordEncoder;

    @InjectMocks
    private SecureAuthenticationStrategy secureAuthenticationStrategy;

    @Test
    void shouldAllowLoginForNewlyCreatedUserWhenPasswordMatches() {
        User user = new User("student01", "123456", "HASHED_123456", "USER");
        user.setEnabled(true);

        given(userRepository.findByUsername("student01")).willReturn(Optional.of(user));
        given(passwordEncoder.matches("123456", "HASHED_123456")).willReturn(true);

        AuthResult result = secureAuthenticationStrategy.authenticate("student01", "123456");

        assertTrue(result.isSuccess());
        assertEquals("SECURE", result.getMode());
    }

    @Test
    void shouldRejectSqlInjectionPayloadInSecureMode() {
        User user = new User("admin", "123456", "HASHED_123456", "ADMIN");
        user.setEnabled(true);

        given(userRepository.findByUsername("admin")).willReturn(Optional.of(user));
        given(passwordEncoder.matches("' OR '1'='1", "HASHED_123456")).willReturn(false);

        AuthResult result = secureAuthenticationStrategy.authenticate("admin", "' OR '1'='1");

        assertFalse(result.isSuccess());
        assertEquals("FAILED", result.getStatus());
    }
}
