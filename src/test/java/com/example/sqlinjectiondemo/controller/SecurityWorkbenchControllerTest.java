package com.example.sqlinjectiondemo.controller;

import com.example.sqlinjectiondemo.model.FileScanResult;
import com.example.sqlinjectiondemo.model.SecurityFinding;
import com.example.sqlinjectiondemo.service.CsrfService;
import com.example.sqlinjectiondemo.service.SecurityLogService;
import com.example.sqlinjectiondemo.service.SecurityWorkbenchService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.mock.web.MockMultipartFile;
import org.springframework.test.web.servlet.MockMvc;

import java.util.List;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.doNothing;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.multipart;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest(SecurityWorkbenchController.class)
class SecurityWorkbenchControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private SecurityWorkbenchService securityWorkbenchService;

    @MockBean
    private SecurityLogService securityLogService;

    @MockBean
    private CsrfService csrfService;

    @Test
    void workbenchShouldRenderForAdminSession() throws Exception {
        given(csrfService.ensureToken(org.mockito.ArgumentMatchers.any())).willReturn("token-123");

        mockMvc.perform(get("/security-workbench")
                        .sessionAttr("currentUser", "admin")
                        .sessionAttr("currentRole", "ADMIN"))
                .andExpect(status().isOk())
                .andExpect(content().string(org.hamcrest.Matchers.containsString("Phân tích bảo mật")));
    }

    @Test
    void fileScanShouldRenderResult() throws Exception {
        MockMultipartFile file = new MockMultipartFile("file", "sample.txt", "text/plain", "hello".getBytes());
        FileScanResult result = new FileScanResult(
                "sample.txt", "text/plain", 5, "sha", "md5", "LOW", 5,
                "Không phát hiện rủi ro đáng kể.",
                List.of(new SecurityFinding("LOW", "OK", "No issue"))
        );

        given(csrfService.isValid(org.mockito.ArgumentMatchers.any(), eq("token-123"))).willReturn(true);
        given(csrfService.ensureToken(org.mockito.ArgumentMatchers.any())).willReturn("token-123");
        given(securityWorkbenchService.analyzeFile(file)).willReturn(result);
        doNothing().when(securityLogService).saveWorkbenchEvent(anyString(), anyString(), anyString(), anyString(), org.mockito.ArgumentMatchers.anyInt(), anyString(), anyString());

        mockMvc.perform(multipart("/security-workbench/file-scan")
                        .file(file)
                        .param("csrfToken", "token-123")
                        .sessionAttr("currentUser", "admin")
                        .sessionAttr("currentRole", "ADMIN"))
                .andExpect(status().isOk())
                .andExpect(content().string(org.hamcrest.Matchers.containsString("sample.txt")));
    }
}
