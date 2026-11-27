package com.apisecurity.monitor.requestlog.web;

import com.apisecurity.monitor.anomaly.endpointscanning.config.EndpointScanningDetectionProperties;
import com.apisecurity.monitor.anomaly.payload.config.QueryPayloadDetectionProperties;
import com.apisecurity.monitor.anomaly.payload.service.JsonRequestBodyPayloadInspector;
import com.apisecurity.monitor.anomaly.payload.service.PayloadSignatureDetector;
import com.apisecurity.monitor.requestlog.config.RequestLoggingProperties;
import com.apisecurity.monitor.requestlog.model.RequestLogData;
import com.apisecurity.monitor.requestlog.service.ApiRequestLogService;
import com.apisecurity.monitor.security.SecurityConfiguration;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.ResponseEntity;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.net.URI;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest(controllers = ApiRequestLoggingFilterMvcIntegrationTest.PathTestController.class)
@Import({
        SecurityConfiguration.class,
        ApiRequestLoggingFilter.class,
        RequestLoggingProperties.class,
        QueryPayloadDetectionProperties.class,
        PayloadSignatureDetector.class,
        EndpointScanningDetectionProperties.class,
        ApiRequestLoggingFilterMvcIntegrationTest.PathTestController.class
})
@TestPropertySource(properties = {
        "monitoring.security.admin-username=admin",
        "monitoring.security.admin-password=test-only-password"
})
class ApiRequestLoggingFilterMvcIntegrationTest {

    private static final String REDACTED_SUSPICIOUS_PATH = "/[suspicious-path-redacted]";

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private EndpointScanningDetectionProperties endpointScanningProperties;

    @MockitoBean
    private ApiRequestLogService requestLogService;

    @MockitoBean
    private JsonRequestBodyPayloadInspector jsonRequestBodyPayloadInspector;

    @Test
    void distinctSafeMissingUrlsPreserveEnoughDistinctEvidenceForEndpointScanning() throws Exception {
        for (int pathNumber = 1; pathNumber <= 8; pathNumber++) {
            mockMvc.perform(get("/mvc-path-test/missing-" + pathNumber)
                            .with(user("admin").roles("ADMIN")))
                    .andExpect(status().isNotFound());
        }

        List<RequestLogData> logged = captureLoggedRequests(8);
        assertThat(logged).allSatisfy(data -> assertThat(data.responseStatus()).isEqualTo(404));
        assertThat(logged).extracting(RequestLogData::requestPath)
                .containsExactlyInAnyOrder(
                        "/mvc-path-test/missing-1",
                        "/mvc-path-test/missing-2",
                        "/mvc-path-test/missing-3",
                        "/mvc-path-test/missing-4",
                        "/mvc-path-test/missing-5",
                        "/mvc-path-test/missing-6",
                        "/mvc-path-test/missing-7",
                        "/mvc-path-test/missing-8");
        assertThat(logged.stream().map(RequestLogData::requestPath).distinct().count())
                .isGreaterThanOrEqualTo(endpointScanningProperties.getDistinctPathThreshold());
        assertThat(logged).hasSizeGreaterThanOrEqualTo(
                endpointScanningProperties.getMinimumUnsuccessfulRequests());
    }

    @Test
    void repeatedMissingUrlPreservesOneStablePath() throws Exception {
        for (int requestNumber = 0; requestNumber < 3; requestNumber++) {
            mockMvc.perform(get("/mvc-path-test/repeated-missing")
                            .with(user("admin").roles("ADMIN")))
                    .andExpect(status().isNotFound());
        }

        assertThat(captureLoggedRequests(3)).extracting(RequestLogData::requestPath)
                .containsOnly("/mvc-path-test/repeated-missing");
    }

    @Test
    void genuineParameterizedControllerRouteRemainsNormalized() throws Exception {
        mockMvc.perform(get("/mvc-path-test/items/9284")
                        .with(user("admin").roles("ADMIN")))
                .andExpect(status().isOk());

        assertThat(captureLoggedRequests(1).getFirst().requestPath())
                .isEqualTo("/mvc-path-test/items/{itemId}");
    }

    @Test
    void controllerGeneratedNotFoundResponseRetainsItsRouteTemplate() throws Exception {
        mockMvc.perform(get("/mvc-path-test/items/9284/not-found")
                        .with(user("admin").roles("ADMIN")))
                .andExpect(status().isNotFound());

        RequestLogData logged = captureLoggedRequests(1).getFirst();
        assertThat(logged.responseStatus()).isEqualTo(404);
        assertThat(logged.requestPath()).isEqualTo("/mvc-path-test/items/{itemId}/not-found");
    }

    @Test
    void suspiciousMissingResourcePathRemainsRedacted() throws Exception {
        mockMvc.perform(get(URI.create(
                                "/mvc-path-test/1%20UNION%20SELECT%20secret%20FROM%20users"))
                        .with(user("admin").roles("ADMIN")))
                .andExpect(status().isNotFound());

        RequestLogData logged = captureLoggedRequests(1).getFirst();
        assertThat(logged.requestPath()).isEqualTo(REDACTED_SUSPICIOUS_PATH)
                .doesNotContain("UNION", "SELECT", "secret");
    }

    private List<RequestLogData> captureLoggedRequests(int expectedCount) {
        ArgumentCaptor<RequestLogData> captor = ArgumentCaptor.forClass(RequestLogData.class);
        verify(requestLogService, times(expectedCount)).save(captor.capture(), anyList());
        return captor.getAllValues();
    }

    @RestController
    @RequestMapping("/mvc-path-test/items")
    public static class PathTestController {

        @GetMapping("/{itemId}")
        String find(@PathVariable String itemId) {
            return "found";
        }

        @GetMapping("/{itemId}/not-found")
        ResponseEntity<Void> notFound(@PathVariable String itemId) {
            return ResponseEntity.notFound().build();
        }
    }
}
