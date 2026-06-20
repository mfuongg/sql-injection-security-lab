package com.example.sqlinjectiondemo.controller;

import com.example.sqlinjectiondemo.entity.User;
import com.example.sqlinjectiondemo.model.DashboardStats;
import com.example.sqlinjectiondemo.service.AuthService;
import com.example.sqlinjectiondemo.service.SecurityLogService;
import com.example.sqlinjectiondemo.service.SqlInjectionDetectorService;
import com.example.sqlinjectiondemo.service.UserService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.test.web.servlet.MockMvc;

import java.util.List;
import java.util.Optional;

import static org.hamcrest.Matchers.containsString;
import static org.mockito.BDDMockito.given;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest(AuthController.class)
class DashboardTemplateRenderingTest {

    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private AuthService authService;

    @MockBean
    private SqlInjectionDetectorService detectorService;

    @MockBean
    private SecurityLogService securityLogService;

    @MockBean
    private UserService userService;

    @Test
    void dashboardShouldRenderForNewlyCreatedUserSession() throws Exception {
        User user = new User("student01", "123456", "$2a$10$demoHash", "USER");
        user.setEnabled(true);
        user.setFailedAttempts(0);

        given(userService.findByUsername("student01")).willReturn(Optional.of(user));
        given(securityLogService.buildStats()).willReturn(new DashboardStats(0, 0, 0, 0, 0, 0, 0));
        given(securityLogService.calculateSystemSecurityScore()).willReturn(92);
        given(securityLogService.calculateUserTrustScore("student01")).willReturn(100);
        given(securityLogService.findRecentByUsername("student01", 8)).willReturn(List.of());
        given(securityLogService.countByUsername("student01")).willReturn(0L);
        given(securityLogService.countSuspiciousByUsername("student01")).willReturn(0L);
        given(securityLogService.countByUsernameAndStatus("student01", "SUCCESS")).willReturn(0L);
        given(securityLogService.countByUsernameAndStatus("student01", "FAILED")).willReturn(0L);
        given(securityLogService.countByUsernameAndStatus("student01", "BLOCKED")).willReturn(0L);
        given(securityLogService.countByUsernameAndMode("student01", "SECURE")).willReturn(0L);
        given(securityLogService.countByUsernameAndMode("student01", "VULNERABLE")).willReturn(0L);
        given(securityLogService.findRecentSuspicious(8)).willReturn(List.of());
        given(securityLogService.findRecentHighRisk(6)).willReturn(List.of());

        mockMvc.perform(get("/dashboard")
                        .sessionAttr("currentUser", "student01")
                        .sessionAttr("currentRole", "USER")
                        .sessionAttr("loginMode", "SECURE")
                        .sessionAttr("detectorResult", "No suspicious keyword detected")
                        .sessionAttr("loginMessage", "Đăng nhập thành công."))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("Bảng điều khiển cá nhân")));
    }
}
