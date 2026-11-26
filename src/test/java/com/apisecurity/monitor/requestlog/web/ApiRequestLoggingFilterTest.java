package com.apisecurity.monitor.requestlog.web;

import com.apisecurity.monitor.anomaly.payload.config.QueryPayloadDetectionProperties;
import com.apisecurity.monitor.anomaly.payload.model.PayloadDetectionFinding;
import com.apisecurity.monitor.anomaly.payload.model.PayloadDetectionFinding.InputLocation;
import com.apisecurity.monitor.anomaly.payload.model.PayloadDetectionFinding.SignatureIdentifier;
import com.apisecurity.monitor.anomaly.payload.service.JsonRequestBodyPayloadInspector;
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
import org.springframework.web.servlet.HandlerMapping;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.ArgumentMatchers.argThat;
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

    @Mock
    private JsonRequestBodyPayloadInspector jsonBodyInspector;

    private QueryPayloadDetectionProperties payloadProperties;
    private ApiRequestLoggingFilter filter;

    @BeforeEach
    void setUp() {
        payloadProperties = new QueryPayloadDetectionProperties();
        filter = new ApiRequestLoggingFilter(
                service,
                new RequestLoggingProperties(),
                payloadProperties,
                payloadSignatureDetector,
                jsonBodyInspector);
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
        verify(payloadSignatureDetector, never()).detectPath(any());
        verify(jsonBodyInspector, never()).inspect(any());
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

    @Test
    void inspectsFullyConsumedJsonWithoutChangingDownstreamContent() throws Exception {
        byte[] body = "{\"comment\":\"<script>alert(1)</script>\"}"
                .getBytes(StandardCharsets.UTF_8);
        PayloadDetectionFinding bodyFinding = finding(
                SecurityEventType.XSS_ATTEMPT,
                InputLocation.REQUEST_BODY,
                SignatureIdentifier.XSS_SCRIPT_TAG);
        MockHttpServletRequest request = jsonRequest("POST", "/api/demo/payload", body);
        AtomicReference<byte[]> downstreamBody = new AtomicReference<>();
        when(jsonBodyInspector.inspect(argThat(cached -> Arrays.equals(cached, body))))
                .thenReturn(List.of(bodyFinding));
        FilterChain chain = (servletRequest, servletResponse) ->
                downstreamBody.set(servletRequest.getInputStream().readAllBytes());

        filter.doFilter(request, new MockHttpServletResponse(), chain);

        assertThat(downstreamBody.get()).containsExactly(body);
        ArgumentCaptor<RequestLogData> dataCaptor = ArgumentCaptor.forClass(RequestLogData.class);
        verify(service).save(dataCaptor.capture(), eq(List.of(bodyFinding)));
        assertThat(dataCaptor.getValue().requestPath()).isEqualTo("/api/demo/payload")
                .doesNotContain("comment", "script", "alert");
    }

    @Test
    void skipsUnreadAndPartiallyConsumedJsonBodies() throws Exception {
        byte[] body = "{\"comment\":\"<script>alert(1)</script>\"}"
                .getBytes(StandardCharsets.UTF_8);

        filter.doFilter(
                jsonRequest("POST", "/api/demo/payload", body),
                new MockHttpServletResponse(),
                new MockFilterChain());

        FilterChain partialReader = (servletRequest, servletResponse) ->
                servletRequest.getInputStream().readNBytes(5);
        filter.doFilter(
                jsonRequest("POST", "/api/demo/payload", body),
                new MockHttpServletResponse(),
                partialReader);

        verify(jsonBodyInspector, never()).inspect(any());
    }

    @Test
    void skipsOversizedUnknownLengthCompressedAndUnsupportedBodies() throws Exception {
        payloadProperties.setMaxBodyCacheBytes(8);
        byte[] body = "{\"value\":\"longer than eight bytes\"}".getBytes(StandardCharsets.UTF_8);
        FilterChain reader = (servletRequest, servletResponse) ->
                servletRequest.getInputStream().readAllBytes();

        filter.doFilter(jsonRequest("POST", "/api/test", body), new MockHttpServletResponse(), reader);

        MockHttpServletRequest unknownLength = new MockHttpServletRequest("POST", "/api/test") {
            @Override
            public long getContentLengthLong() {
                return -1;
            }
        };
        unknownLength.setContentType("application/json");
        unknownLength.setContent("{}".getBytes(StandardCharsets.UTF_8));
        filter.doFilter(unknownLength, new MockHttpServletResponse(), reader);

        MockHttpServletRequest compressed = jsonRequest("POST", "/api/test", "{}".getBytes(StandardCharsets.UTF_8));
        compressed.addHeader("Content-Encoding", "gzip");
        filter.doFilter(compressed, new MockHttpServletResponse(), reader);

        MockHttpServletRequest unsupportedType = request("POST", "/api/test");
        unsupportedType.setContentType("text/plain");
        unsupportedType.setContent("<script>".getBytes(StandardCharsets.UTF_8));
        filter.doFilter(unsupportedType, new MockHttpServletResponse(), reader);

        MockHttpServletRequest unsupportedCharset = request("POST", "/api/test");
        unsupportedCharset.setContentType("application/json;charset=UTF-16");
        unsupportedCharset.setContent("{}".getBytes(StandardCharsets.UTF_16));
        filter.doFilter(unsupportedCharset, new MockHttpServletResponse(), reader);

        verify(jsonBodyInspector, never()).inspect(any());
    }

    @Test
    void skipsBodyWhenTheCachingWrapperReportsOverflow() throws Exception {
        payloadProperties.setMaxBodyCacheBytes(8);
        byte[] body = "{\"value\":\"larger than declared\"}".getBytes(StandardCharsets.UTF_8);
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/api/test") {
            @Override
            public long getContentLengthLong() {
                return 8;
            }
        };
        request.setContentType("application/json");
        request.setContent(body);
        FilterChain reader = (servletRequest, servletResponse) ->
                servletRequest.getInputStream().readAllBytes();

        filter.doFilter(request, new MockHttpServletResponse(), reader);

        verify(jsonBodyInspector, never()).inspect(any());
    }

    @Test
    void combinesMixedLocationFindingsAndIsolatesInspectionFailures() throws Exception {
        byte[] body = "{\"comment\":\"<script>\"}".getBytes(StandardCharsets.UTF_8);
        PayloadDetectionFinding pathFinding = finding(
                SecurityEventType.SQL_INJECTION_ATTEMPT,
                InputLocation.REQUEST_PATH,
                SignatureIdentifier.SQLI_UNION_SELECT);
        PayloadDetectionFinding bodyFinding = finding(
                SecurityEventType.XSS_ATTEMPT,
                InputLocation.REQUEST_BODY,
                SignatureIdentifier.XSS_SCRIPT_TAG);
        MockHttpServletRequest request = jsonRequest("POST", "/reports/1%20UNION%20SELECT%20password", body);
        request.setQueryString("q=<script>");
        when(payloadSignatureDetector.detect(request.getQueryString()))
                .thenThrow(new IllegalStateException("query detector unavailable"));
        when(payloadSignatureDetector.detectPath(request.getRequestURI())).thenReturn(List.of(pathFinding));
        when(jsonBodyInspector.inspect(any())).thenReturn(List.of(bodyFinding));
        FilterChain reader = (servletRequest, servletResponse) ->
                servletRequest.getInputStream().readAllBytes();

        assertThatCode(() -> filter.doFilter(request, new MockHttpServletResponse(), reader))
                .doesNotThrowAnyException();

        verify(service).save(any(RequestLogData.class), eq(List.of(pathFinding, bodyFinding)));
    }

    @Test
    void bodyInspectionFailurePreservesPathFindingsAndOriginalResponse() throws Exception {
        byte[] body = "{\"comment\":\"<script>\"}".getBytes(StandardCharsets.UTF_8);
        PayloadDetectionFinding pathFinding = finding(
                SecurityEventType.XSS_ATTEMPT,
                InputLocation.REQUEST_PATH,
                SignatureIdentifier.XSS_SCRIPT_TAG);
        MockHttpServletRequest request = jsonRequest("POST", "/unsafe/<script>", body);
        when(payloadSignatureDetector.detectPath(request.getRequestURI())).thenReturn(List.of(pathFinding));
        when(jsonBodyInspector.inspect(any())).thenThrow(new IllegalStateException("body detector unavailable"));
        MockHttpServletResponse response = new MockHttpServletResponse();
        FilterChain chain = (servletRequest, servletResponse) -> {
            servletRequest.getInputStream().readAllBytes();
            ((MockHttpServletResponse) servletResponse).setStatus(201);
            servletResponse.getWriter().write("created");
        };

        filter.doFilter(request, response, chain);

        verify(service).save(any(RequestLogData.class), eq(List.of(pathFinding)));
        assertThat(response.getStatus()).isEqualTo(201);
        assertThat(response.getContentAsString()).isEqualTo("created");
    }

    @Test
    void pathInspectionFailurePreservesQueryAndBodyFindings() throws Exception {
        byte[] body = "{\"comment\":\"<script>\"}".getBytes(StandardCharsets.UTF_8);
        PayloadDetectionFinding queryFinding = finding(
                SecurityEventType.SQL_INJECTION_ATTEMPT,
                InputLocation.QUERY_PARAMETER,
                SignatureIdentifier.SQLI_UNION_SELECT);
        PayloadDetectionFinding bodyFinding = finding(
                SecurityEventType.XSS_ATTEMPT,
                InputLocation.REQUEST_BODY,
                SignatureIdentifier.XSS_SCRIPT_TAG);
        MockHttpServletRequest request = jsonRequest("POST", "/api/demo/payload", body);
        request.setQueryString("q=1+UNION+SELECT+password");
        when(payloadSignatureDetector.detect(request.getQueryString())).thenReturn(List.of(queryFinding));
        when(payloadSignatureDetector.detectPath(request.getRequestURI()))
                .thenThrow(new IllegalStateException("path detector unavailable"));
        when(jsonBodyInspector.inspect(any())).thenReturn(List.of(bodyFinding));
        FilterChain reader = (servletRequest, servletResponse) ->
                servletRequest.getInputStream().readAllBytes();

        filter.doFilter(request, new MockHttpServletResponse(), reader);

        verify(service).save(any(RequestLogData.class), eq(List.of(queryFinding, bodyFinding)));
    }

    @Test
    void storesMvcRouteTemplateInsteadOfConcretePath() throws Exception {
        PayloadDetectionFinding pathFinding = finding(
                SecurityEventType.SQL_INJECTION_ATTEMPT,
                InputLocation.REQUEST_PATH,
                SignatureIdentifier.SQLI_UNION_SELECT);
        MockHttpServletRequest request = request("GET", "/orders/private-token-value");
        when(payloadSignatureDetector.detectPath(request.getRequestURI())).thenReturn(List.of(pathFinding));
        FilterChain chain = (servletRequest, servletResponse) -> servletRequest.setAttribute(
                HandlerMapping.BEST_MATCHING_PATTERN_ATTRIBUTE, "/orders/{orderId}");

        filter.doFilter(request, new MockHttpServletResponse(), chain);

        assertThat(captureLoggedData().requestPath()).isEqualTo("/orders/{orderId}")
                .doesNotContain("private-token-value");
        verify(service).save(any(RequestLogData.class), eq(List.of(pathFinding)));
    }

    @Test
    void redactsSuspiciousUnmatchedPathBeforePersistence() throws Exception {
        PayloadDetectionFinding pathFinding = finding(
                SecurityEventType.XSS_ATTEMPT,
                InputLocation.REQUEST_PATH,
                SignatureIdentifier.XSS_SCRIPT_TAG);
        MockHttpServletRequest request = request("GET", "/missing/<script>alert(1)</script>");
        when(payloadSignatureDetector.detectPath(request.getRequestURI())).thenReturn(List.of(pathFinding));

        filter.doFilter(request, new MockHttpServletResponse(), new MockFilterChain());

        assertThat(captureLoggedData().requestPath()).isEqualTo("/[suspicious-path-redacted]")
                .doesNotContain("script", "alert");
        verify(service).save(any(RequestLogData.class), eq(List.of(pathFinding)));
    }

    private MockHttpServletRequest request(String method, String path) {
        return new MockHttpServletRequest(method, path);
    }

    private MockHttpServletRequest jsonRequest(String method, String path, byte[] body) {
        MockHttpServletRequest request = request(method, path);
        request.setContentType("application/json;charset=UTF-8");
        request.setContent(body);
        return request;
    }

    private PayloadDetectionFinding finding(
            SecurityEventType eventType,
            InputLocation inputLocation,
            SignatureIdentifier signatureIdentifier
    ) {
        return new PayloadDetectionFinding(eventType, inputLocation, signatureIdentifier);
    }

    private RequestLogData captureLoggedData() {
        ArgumentCaptor<RequestLogData> captor = ArgumentCaptor.forClass(RequestLogData.class);
        verify(service).save(captor.capture(), anyList());
        return captor.getValue();
    }
}
