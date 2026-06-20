package com.example.sqlinjectiondemo.service;

import com.example.sqlinjectiondemo.entity.User;
import com.example.sqlinjectiondemo.repository.UserRepository;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

@ExtendWith(MockitoExtension.class)
class UserServiceTest {

    @Mock
    private UserRepository userRepository;

    @Mock
    private PasswordEncoder passwordEncoder;

    @InjectMocks
    private UserService userService;

    @Test
    void createUserShouldStoreHashAndResetFailureCounter() {
        given(userRepository.findByUsername("student01")).willReturn(Optional.empty());
        given(passwordEncoder.encode("123456")).willReturn("HASHED_123456");
        given(userRepository.save(any(User.class))).willAnswer(invocation -> invocation.getArgument(0));

        User user = userService.createUser("student01", "123456", "USER");

        assertEquals("student01", user.getUsername());
        assertEquals("123456", user.getPassword());
        assertEquals("HASHED_123456", user.getPasswordHash());
        assertEquals(0, user.getFailedAttempts());
        assertTrue(user.isEnabled());
    }

    @Test
    void createUserShouldRejectDuplicateUsernameWithShortMessage() {
        given(userRepository.findByUsername("student01")).willReturn(Optional.of(new User("student01", "123456", "HASHED", "USER")));

        IllegalArgumentException ex = assertThrows(IllegalArgumentException.class,
                () -> userService.createUser("student01", "123456", "USER"));

        assertEquals("Tên đăng nhập đã tồn tại.", ex.getMessage());
    }

    @Test
    void findAllShouldSortByIdAscending() {
        User second = new User("second", "123456", "HASH2", "USER");
        second.setId(2L);
        User first = new User("first", "123456", "HASH1", "USER");
        first.setId(1L);
        given(userRepository.findAll()).willReturn(List.of(second, first));

        List<User> users = userService.findAll();

        assertEquals(List.of(1L, 2L), users.stream().map(User::getId).toList());
    }

    @Test
    void recordFailureShouldLockAccountAfterFiveAttempts() {
        User user = new User("student01", "123456", "HASHED_123456", "USER");
        given(userRepository.findByUsername("student01")).willReturn(Optional.of(user));

        for (int i = 0; i < 5; i++) {
            userService.recordFailure("student01");
        }

        assertEquals(5, user.getFailedAttempts());
        assertNotNull(user.getLockedUntil());
        verify(userRepository, times(5)).save(user);
    }
}
