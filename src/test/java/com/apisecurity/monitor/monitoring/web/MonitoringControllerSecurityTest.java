package com.apisecurity.monitor.monitoring.web;

import com.apisecurity.monitor.anomaly.bruteforce.config.BruteForceDetectionProperties;
import com.apisecurity.monitor.anomaly.bruteforce.service.BruteForceAttemptTracker;
import com.apisecurity.monitor.anomaly.bruteforce.service.BruteForceAuthenticationEventListener;
import com.apisecurity.monitor.anomaly.payload.config.QueryPayloadDetectionProperties;
import com.apisecurity.monitor.anomaly.payload.service.JsonRequestBodyPayloadInspector;
import com.apisecurity.monitor.anomaly.payload.service.PayloadSignatureDetector;
import com.apisecurity.monitor.monitoring.dto.MonitoringSummaryResponse;
import com.apisecurity.monitor.monitoring.dto.PagedResponse;
import com.apisecurity.monitor.monitoring.config.MonitoringTimeConfiguration;
import com.apisecurity.monitor.monitoring.service.MonitoringQueryService;
import com.apisecurity.monitor.requestlog.config.RequestLoggingProperties;
import com.apisecurity.monitor.requestlog.service.ApiRequestLogService;
import com.apisecurity.monitor.security.SecurityConfiguration;
import com.apisecurity.monitor.securityevent.model.SecurityEventData;
import com.apisecurity.monitor.securityevent.model.SecurityEventType;
import com.apisecurity.monitor.securityevent.service.SecurityEventService;
import com.apisecurity.monitor.testapi.TestController;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import java.time.Instant;
import java.util.List;

import static org.hamcrest.Matchers.containsString;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest(controllers = {
        MonitoringController.class,
        MonitoringPageController.class,
        TestController.class
})
@Import({
        SecurityConfiguration.class,
        MonitoringTimeConfiguration.class,
        BruteForceDetectionProperties.class,
        BruteForceAttemptTracker.class,
        BruteForceAuthenticationEventListener.class
})
@TestPropertySource(properties = {
        "monitoring.security.admin-username=admin",
        "monitoring.security.admin-password=test-only-password"
})
class MonitoringControllerSecurityTest {

    private static final Instant GENERATED_AT = Instant.parse("2026-11-16T08:00:00Z");

    @Autowired
    private MockMvc mockMvc;

    @MockitoBean
    private MonitoringQueryService monitoringQueryService;

    @MockitoBean
    private ApiRequestLogService apiRequestLogService;

    @MockitoBean
    private RequestLoggingProperties requestLoggingProperties;

    @MockitoBean
    private PayloadSignatureDetector payloadSignatureDetector;

    @MockitoBean
    private QueryPayloadDetectionProperties queryPayloadDetectionProperties;

    @MockitoBean
    private JsonRequestBodyPayloadInspector jsonRequestBodyPayloadInspector;

    @MockitoBean
    private SecurityEventService securityEventService;

    @Test
    void redirectsUnauthenticatedMonitoringApiAndPageToLogin() throws Exception {
        mockMvc.perform(get("/api/monitoring/summary"))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/login"));

        mockMvc.perform(get("/monitoring"))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/login"));
    }

    @Test
    void localAdministratorCanSignInAndReadMonitoringApi() throws Exception {
        when(monitoringQueryService.getSummary())
                .thenReturn(new MonitoringSummaryResponse(100, 20, 2, 4, 1, GENERATED_AT));

        MvcResult login = mockMvc.perform(post("/login")
                        .with(csrf())
                        .param("username", "admin")
                        .param("password", "test-only-password"))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/monitoring"))
                .andReturn();

        MockHttpSession session = (MockHttpSession) login.getRequest().getSession(false);
        mockMvc.perform(get("/api/monitoring/summary").session(session))
                .andExpect(status().isOk())
                .andExpect(content().contentTypeCompatibleWith("application/json"))
                .andExpect(jsonPath("$.totalRequests").value(100))
                .andExpect(jsonPath("$.errorsLast24Hours").value(2))
                .andExpect(jsonPath("$.totalSecurityEvents").value(4));
    }

    @Test
    void administratorCanReadPaginatedEndpoints() throws Exception {
        when(monitoringQueryService.getRequests(0, 20))
                .thenReturn(new PagedResponse<>(List.of(), 0, 20, 0, 0, true, true));
        when(monitoringQueryService.getEvents(0, 20))
                .thenReturn(new PagedResponse<>(List.of(), 0, 20, 0, 0, true, true));

        mockMvc.perform(get("/api/monitoring/requests").with(user("admin").roles("ADMIN")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.content").isEmpty())
                .andExpect(jsonPath("$.size").value(20));

        mockMvc.perform(get("/api/monitoring/events").with(user("admin").roles("ADMIN")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.content").isEmpty())
                .andExpect(jsonPath("$.size").value(20));
    }

    @Test
    void testTrafficEndpointRemainsPublic() throws Exception {
        mockMvc.perform(get("/api/test"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.message").value("API security monitor is running"));
    }

    @Test
    void authenticatedAdministratorCanLoadDashboardResource() throws Exception {
        mockMvc.perform(get("/monitoring/index.html").with(user("admin").roles("ADMIN")))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("API Security Monitoring Dashboard")))
                .andExpect(content().string(containsString("Loading requests")))
                .andExpect(content().string(containsString("Detected security events")))
                .andExpect(content().string(containsString("signature indicator")))
                .andExpect(content().string(containsString("BRUTE_FORCE_ATTEMPT")))
                .andExpect(content().string(containsString("textContent")));
    }

    @Test
    void csrfProtectsLoginSubmission() throws Exception {
        mockMvc.perform(post("/login")
                        .param("username", "admin")
                        .param("password", "test-only-password"))
                .andExpect(status().isForbidden());
    }

    @Test
    void authenticationFailureEventsUseTheTrustedServletRemoteAddress() throws Exception {
        for (int attempt = 0; attempt < 5; attempt++) {
            mockMvc.perform(post("/login")
                            .with(csrf())
                            .with(request -> {
                                request.setRemoteAddr("192.0.2.10");
                                return request;
                            })
                            .header("X-Forwarded-For", "203.0.113.99")
                            .param("username", "admin")
                            .param("password", "wrong-password"))
                    .andExpect(status().is3xxRedirection())
                    .andExpect(redirectedUrl("/login?error"));
        }

        org.mockito.ArgumentCaptor<SecurityEventData> captor =
                org.mockito.ArgumentCaptor.forClass(SecurityEventData.class);
        verify(securityEventService).createIfNotSuppressed(captor.capture(), any());
        assertThat(captor.getValue().eventType()).isEqualTo(SecurityEventType.BRUTE_FORCE_ATTEMPT);
        assertThat(captor.getValue().clientIp()).isEqualTo("192.0.2.10");
    }

    @Test
    void successfulAuthenticationEventResetsMatchingFailureHistory() throws Exception {
        performFailedLogins("192.0.2.11", 4);

        mockMvc.perform(post("/login")
                        .with(csrf())
                        .with(request -> {
                            request.setRemoteAddr("192.0.2.11");
                            return request;
                        })
                        .param("username", "admin")
                        .param("password", "test-only-password"))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/monitoring"));

        performFailedLogins("192.0.2.11", 4);

        verify(securityEventService, never()).createIfNotSuppressed(any(), any());
    }

    @Test
    void successfulAuthenticationResetsMixedCaseFailuresForTheSameAccount() throws Exception {
        performFailedLogins("192.0.2.14", "ADMIN", 4);

        mockMvc.perform(post("/login")
                        .with(csrf())
                        .with(request -> {
                            request.setRemoteAddr("192.0.2.14");
                            return request;
                        })
                        .param("username", "admin")
                        .param("password", "test-only-password"))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/monitoring"));

        performFailedLogins("192.0.2.14", "AdMiN", 4);

        verify(securityEventService, never()).createIfNotSuppressed(any(), any());
    }

    @Test
    void csrfAndAuthorizationResponsesAreNotAuthenticationFailures() throws Exception {
        for (int attempt = 0; attempt < 5; attempt++) {
            mockMvc.perform(post("/login")
                            .with(request -> {
                                request.setRemoteAddr("192.0.2.12");
                                return request;
                            })
                            .param("username", "admin")
                            .param("password", "wrong-password"))
                    .andExpect(status().isForbidden());

            mockMvc.perform(get("/monitoring")
                            .with(request -> {
                                request.setRemoteAddr("192.0.2.12");
                                return request;
                            }))
                    .andExpect(status().is3xxRedirection())
                    .andExpect(redirectedUrl("/login"));

            mockMvc.perform(get("/monitoring").with(user("ordinary-user").roles("USER")))
                    .andExpect(status().isForbidden());
        }

        verify(securityEventService, never()).createIfNotSuppressed(any(), any());
    }

    @Test
    void eventPersistenceFailureDoesNotChangeTheFailedLoginResponse() throws Exception {
        doThrow(new IllegalStateException("database unavailable"))
                .when(securityEventService).createIfNotSuppressed(any(), any());

        performFailedLogins("192.0.2.13", 5);

        verify(securityEventService).createIfNotSuppressed(any(), any());
    }

    private void performFailedLogins(String remoteAddress, int attempts) throws Exception {
        performFailedLogins(remoteAddress, "admin", attempts);
    }

    private void performFailedLogins(String remoteAddress, String username, int attempts) throws Exception {
        for (int attempt = 0; attempt < attempts; attempt++) {
            mockMvc.perform(post("/login")
                            .with(csrf())
                            .with(request -> {
                                request.setRemoteAddr(remoteAddress);
                                return request;
                            })
                            .param("username", username)
                            .param("password", "wrong-password"))
                    .andExpect(status().is3xxRedirection())
                    .andExpect(redirectedUrl("/login?error"));
        }
    }
}
