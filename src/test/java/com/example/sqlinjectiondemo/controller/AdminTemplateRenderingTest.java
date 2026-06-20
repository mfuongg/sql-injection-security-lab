package com.example.sqlinjectiondemo.controller;

import com.example.sqlinjectiondemo.entity.User;
import com.example.sqlinjectiondemo.model.DashboardStats;
import com.example.sqlinjectiondemo.model.SecurityTestCaseItem;
import com.example.sqlinjectiondemo.service.PdfReportService;
import com.example.sqlinjectiondemo.service.SecurityAssessmentService;
import com.example.sqlinjectiondemo.service.SecurityLogService;
import com.example.sqlinjectiondemo.service.UserService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.test.web.servlet.MockMvc;

import java.util.List;

import static org.hamcrest.Matchers.containsString;
import static org.mockito.BDDMockito.given;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest(AdminController.class)
class AdminTemplateRenderingTest {

    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private SecurityLogService securityLogService;

    @MockBean
    private UserService userService;

    @MockBean
    private SecurityAssessmentService securityAssessmentService;

    @MockBean
    private PdfReportService pdfReportService;

    @Test
    void monitorRouteShouldRedirectToLogsForAdminSession() throws Exception {
        mockMvc.perform(get("/monitor")
                        .sessionAttr("currentUser", "admin")
                        .sessionAttr("currentRole", "ADMIN"))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/logs"));
    }

    @Test
    void defenseMatrixShouldRenderForAdminSession() throws Exception {
        given(securityLogService.buildStats()).willReturn(new DashboardStats(10, 4, 3, 2, 5, 1, 5));
        given(securityLogService.calculateSystemSecurityScore()).willReturn(59);
        given(securityLogService.countByRiskLevel("CRITICAL")).willReturn(4L);
        given(securityLogService.countByRiskLevel("HIGH")).willReturn(3L);
        given(securityLogService.countByRiskLevel("MEDIUM")).willReturn(2L);
        given(securityLogService.countByRiskLevel("LOW")).willReturn(1L);
        given(securityLogService.findRecentHighRisk(6)).willReturn(List.of());
        given(securityAssessmentService.getRecommendedTestCases()).willReturn(List.of(
                new SecurityTestCaseItem("TC-01", "Kiểm thử secure", "Không lộ lỗi SQL", "Payload demo", "Thông báo ngắn gọn", 10, "Authentication")
        ));
        given(securityAssessmentService.getTotalPoints()).willReturn(100);

        mockMvc.perform(get("/defense-matrix")
                        .sessionAttr("currentUser", "admin")
                        .sessionAttr("currentRole", "ADMIN"))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("Tóm tắt các lớp kiểm soát bảo mật")));
    }

    @Test
    void usersPageShouldRenderSortedAccountScreen() throws Exception {
        User admin = new User("admin", "123456", "$2a$10$hash", "ADMIN");
        admin.setId(1L);
        admin.setEnabled(true);
        given(userService.findAll()).willReturn(List.of(admin));

        mockMvc.perform(get("/users")
                        .sessionAttr("currentUser", "admin")
                        .sessionAttr("currentRole", "ADMIN"))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("Danh sách tài khoản")));
    }
}
