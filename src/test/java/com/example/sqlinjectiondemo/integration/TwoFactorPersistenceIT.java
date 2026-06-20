package com.example.sqlinjectiondemo.integration;

import com.example.sqlinjectiondemo.entity.User;
import com.example.sqlinjectiondemo.repository.UserRepository;
import com.example.sqlinjectiondemo.service.TwoFactorService;
import com.example.sqlinjectiondemo.service.UserService;
import jakarta.persistence.EntityManager;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.containers.MySQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest
@Testcontainers
class TwoFactorPersistenceIT {

    @Container
    static final MySQLContainer<?> MYSQL = new MySQLContainer<>("mysql:8.4")
            .withDatabaseName("sql_injection_demo")
            .withUsername("test")
            .withPassword("test");

    @DynamicPropertySource
    static void configureDatasource(DynamicPropertyRegistry registry) {
        registry.add("spring.datasource.url", MYSQL::getJdbcUrl);
        registry.add("spring.datasource.username", MYSQL::getUsername);
        registry.add("spring.datasource.password", MYSQL::getPassword);
        registry.add("spring.jpa.hibernate.ddl-auto", () -> "update");
        registry.add("spring.sql.init.mode", () -> "never");
    }

    @Autowired
    private UserService userService;
    @Autowired
    private TwoFactorService twoFactorService;
    @Autowired
    private UserRepository userRepository;
    @Autowired
    private EntityManager entityManager;

    @Test
    void enableAndDisableTwoFactorShouldPersistAcrossReloads() {
        User user = userService.createUser("admin2fa_toggle", "123456", "ADMIN");
        User prepared = userService.ensureTwoFactorSecret(user, twoFactorService);
        String secret = prepared.getTwoFactorSecret();
        userService.enableTwoFactor(prepared);
        userService.recordTotpSuccess(prepared, 42L);
        entityManager.flush();
        entityManager.clear();
        User enabledReloaded = userRepository.findByUsername("admin2fa_toggle").orElseThrow();
        assertTrue(enabledReloaded.isTwoFactorEnabled());
        assertEquals(secret, enabledReloaded.getTwoFactorSecret());
        assertEquals(42L, enabledReloaded.getLastTotpCounter());
        userService.disableTwoFactor(enabledReloaded);
        entityManager.flush();
        entityManager.clear();
        User disabledReloaded = userRepository.findByUsername("admin2fa_toggle").orElseThrow();
        assertFalse(disabledReloaded.isTwoFactorEnabled());
        assertEquals(secret, disabledReloaded.getTwoFactorSecret());
        assertNull(disabledReloaded.getLastTotpCounter());
    }
}
