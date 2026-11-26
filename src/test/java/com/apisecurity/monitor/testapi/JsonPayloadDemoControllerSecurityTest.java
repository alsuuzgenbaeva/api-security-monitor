package com.apisecurity.monitor.testapi;

import com.apisecurity.monitor.anomaly.payload.config.QueryPayloadDetectionProperties;
import com.apisecurity.monitor.anomaly.payload.service.JsonRequestBodyPayloadInspector;
import com.apisecurity.monitor.anomaly.payload.service.PayloadSignatureDetector;
import com.apisecurity.monitor.requestlog.config.RequestLoggingProperties;
import com.apisecurity.monitor.requestlog.service.ApiRequestLogService;
import com.apisecurity.monitor.security.SecurityConfiguration;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@ActiveProfiles("demo")
@WebMvcTest(controllers = JsonPayloadDemoController.class)
@Import(SecurityConfiguration.class)
@TestPropertySource(properties = {
        "monitoring.security.admin-username=admin",
        "monitoring.security.admin-password=test-only-password"
})
class JsonPayloadDemoControllerSecurityTest {

    @Autowired
    private MockMvc mockMvc;

    @MockitoBean
    private ApiRequestLogService apiRequestLogService;

    @MockitoBean
    private RequestLoggingProperties requestLoggingProperties;

    @MockitoBean
    private QueryPayloadDetectionProperties queryPayloadDetectionProperties;

    @MockitoBean
    private PayloadSignatureDetector payloadSignatureDetector;

    @MockitoBean
    private JsonRequestBodyPayloadInspector jsonRequestBodyPayloadInspector;

    @Test
    void requiresAuthentication() throws Exception {
        mockMvc.perform(post("/api/demo/payload")
                        .with(csrf())
                        .contentType("application/json")
                        .content("{\"comment\":\"safe\"}"))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/login"));
    }

    @Test
    void requiresAdministratorRole() throws Exception {
        mockMvc.perform(post("/api/demo/payload")
                        .with(user("viewer").roles("USER"))
                        .with(csrf())
                        .contentType("application/json")
                        .content("{\"comment\":\"safe\"}"))
                .andExpect(status().isForbidden());
    }

    @Test
    void retainsCsrfProtection() throws Exception {
        mockMvc.perform(post("/api/demo/payload")
                        .with(user("admin").roles("ADMIN"))
                        .contentType("application/json")
                        .content("{\"comment\":\"safe\"}"))
                .andExpect(status().isForbidden());
    }

    @Test
    void administratorWithCsrfCanSubmitJsonWithoutEchoingIt() throws Exception {
        mockMvc.perform(post("/api/demo/payload")
                        .with(user("admin").roles("ADMIN"))
                        .with(csrf())
                        .contentType("application/json")
                        .content("{\"comment\":\"private submitted value\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.message").value("JSON payload received for monitoring"))
                .andExpect(jsonPath("$.comment").doesNotExist());
    }
}
