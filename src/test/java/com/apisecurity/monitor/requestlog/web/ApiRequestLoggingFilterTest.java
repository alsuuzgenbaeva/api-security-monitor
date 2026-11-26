package com.apisecurity.monitor.requestlog.web;

import com.apisecurity.monitor.anomaly.payload.model.PayloadDetectionFinding;
import com.apisecurity.monitor.anomaly.payload.model.PayloadDetectionFinding.InputLocation;
import com.apisecurity.monitor.anomaly.payload.model.PayloadDetectionFinding.SignatureIdentifier;
import com.apisecurity.monitor.anomaly.payload.service.PayloadSignatureDetector;
import com.apisecurity.monitor.requestlog.config.RequestLoggingProperties;
import com.apisecurity.monitor.requestlog.model.RequestLogData;
import com.apisecurity.monitor.requestlog.service.ApiRequestLogService;
import com.apisecurity.monitor.securityevent.model.SecurityEventType;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import java.io.IOException;
import java.time.Instant;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.nullable;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class ApiRequestLoggingFilterTest {

    @Mock
    private ApiRequestLogService service;

    @Mock
    private PayloadSignatureDetector payloadSignatureDetector;

    private ApiRequestLoggingFilter filter;

    @BeforeEach
    void setUp() {
        filter = new ApiRequestLoggingFilter(
                service, new RequestLoggingProperties(), payloadSignatureDetector);
    }

    @Test
    void logsSuccessfulResponseWithoutQueryString() throws ServletException, IOException {
        MockHttpServletRequest request = request("GET", "/api/test");
        request.setQueryString("token=must-not-be-stored");
        request.setRemoteAddr("127.0.0.1");
        MockHttpServletResponse response = new MockHttpServletResponse();
        Instant before = Instant.now();

        filter.doFilter(request, response, new MockFilterChain());

        RequestLogData logged = captureLoggedData();
        assertThat(logged.requestedAt()).isBetween(before, Instant.now());
        assertThat(logged.clientIp()).isEqualTo("127.0.0.1");
        assertThat(logged.httpMethod()).isEqualTo("GET");
        assertThat(logged.requestPath()).isEqualTo("/api/test").doesNotContain("?").doesNotContain("token");
        assertThat(logged.responseStatus()).isEqualTo(200);
        assertThat(logged.durationMs()).isGreaterThanOrEqualTo(0);
    }

    @Test
    void logsHttpErrorStatus() throws ServletException, IOException {
        MockHttpServletRequest request = request("GET", "/missing");
        MockHttpServletResponse response = new MockHttpServletResponse();
        FilterChain chain = (servletRequest, servletResponse) ->
                ((MockHttpServletResponse) servletResponse).setStatus(404);

        filter.doFilter(request, response, chain);

        assertThat(captureLoggedData().responseStatus()).isEqualTo(404);
    }

    @Test
    void skipsExcludedPaths() throws ServletException, IOException {
        filter.doFilter(request("GET", "/error"), new MockHttpServletResponse(), new MockFilterChain());
        filter.doFilter(request("GET", "/favicon.ico"), new MockHttpServletResponse(), new MockFilterChain());

        verify(service, never()).save(any());
        verify(service, never()).save(any(), anyList());
        verify(payloadSignatureDetector, never()).detect(any());
    }

    @Test
    void persistenceFailureDoesNotChangeOriginalResponse() throws ServletException, IOException {
        doThrow(new IllegalStateException("database unavailable")).when(service).save(any(), anyList());
        MockHttpServletResponse response = new MockHttpServletResponse();
        FilterChain chain = (servletRequest, servletResponse) -> {
            ((MockHttpServletResponse) servletResponse).setStatus(201);
            servletResponse.getWriter().write("created");
        };

        assertThatCode(() -> filter.doFilter(request("POST", "/api/test"), response, chain))
                .doesNotThrowAnyException();
        assertThat(response.getStatus()).isEqualTo(201);
        assertThat(response.getContentAsString()).isEqualTo("created");
    }

    @Test
    void forwardsPrivacySafeQueryFindingsWithoutPersistingRawQuery() throws ServletException, IOException {
        PayloadDetectionFinding finding = new PayloadDetectionFinding(
                SecurityEventType.XSS_ATTEMPT,
                InputLocation.QUERY_PARAMETER,
                SignatureIdentifier.XSS_SCRIPT_TAG);
        MockHttpServletRequest request = request("GET", "/api/test");
        request.setQueryString("token=secret-value&q=%3Cscript%3E");
        when(payloadSignatureDetector.detect(request.getQueryString()))
                .thenReturn(List.of(finding));

        filter.doFilter(request, new MockHttpServletResponse(), new MockFilterChain());

        ArgumentCaptor<RequestLogData> dataCaptor = ArgumentCaptor.forClass(RequestLogData.class);
        verify(service).save(dataCaptor.capture(), eq(List.of(finding)));
        assertThat(dataCaptor.getValue().requestPath()).isEqualTo("/api/test")
                .doesNotContain("token", "secret-value", "script");
    }

    @Test
    void queryDetectionFailureStillLogsRequestAndPreservesResponse() throws ServletException, IOException {
        when(payloadSignatureDetector.detect(nullable(String.class)))
                .thenThrow(new IllegalStateException("detector unavailable"));
        MockHttpServletResponse response = new MockHttpServletResponse();
        FilterChain chain = (servletRequest, servletResponse) -> {
            ((MockHttpServletResponse) servletResponse).setStatus(202);
            servletResponse.getWriter().write("accepted");
        };

        filter.doFilter(request("GET", "/api/test"), response, chain);

        verify(service).save(any(RequestLogData.class), eq(List.of()));
        assertThat(response.getStatus()).isEqualTo(202);
        assertThat(response.getContentAsString()).isEqualTo("accepted");
    }

    private MockHttpServletRequest request(String method, String path) {
        return new MockHttpServletRequest(method, path);
    }

    private RequestLogData captureLoggedData() {
        ArgumentCaptor<RequestLogData> captor = ArgumentCaptor.forClass(RequestLogData.class);
        verify(service).save(captor.capture(), anyList());
        return captor.getValue();
    }
}
