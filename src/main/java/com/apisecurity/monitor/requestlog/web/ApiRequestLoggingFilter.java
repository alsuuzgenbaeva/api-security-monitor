package com.apisecurity.monitor.requestlog.web;

import com.apisecurity.monitor.anomaly.payload.config.QueryPayloadDetectionProperties;
import com.apisecurity.monitor.anomaly.payload.model.PayloadDetectionFinding;
import com.apisecurity.monitor.anomaly.payload.model.PayloadDetectionFinding.InputLocation;
import com.apisecurity.monitor.anomaly.payload.service.JsonRequestBodyPayloadInspector;
import com.apisecurity.monitor.anomaly.payload.service.PayloadSignatureDetector;
import com.apisecurity.monitor.requestlog.config.RequestLoggingProperties;
import com.apisecurity.monitor.requestlog.model.RequestLogData;
import com.apisecurity.monitor.requestlog.service.ApiRequestLogService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.InvalidMediaTypeException;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.servlet.HandlerMapping;
import org.springframework.web.servlet.resource.ResourceHttpRequestHandler;
import org.springframework.web.util.ContentCachingRequestWrapper;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.TimeUnit;

@Component
public class ApiRequestLoggingFilter extends OncePerRequestFilter {

    private static final Logger logger = LoggerFactory.getLogger(ApiRequestLoggingFilter.class);
    private static final String REDACTED_SUSPICIOUS_PATH = "/[suspicious-path-redacted]";

    private final ApiRequestLogService requestLogService;
    private final RequestLoggingProperties properties;
    private final QueryPayloadDetectionProperties payloadProperties;
    private final PayloadSignatureDetector payloadSignatureDetector;
    private final JsonRequestBodyPayloadInspector jsonBodyInspector;

    public ApiRequestLoggingFilter(
            ApiRequestLogService requestLogService,
            RequestLoggingProperties properties,
            QueryPayloadDetectionProperties payloadProperties,
            PayloadSignatureDetector payloadSignatureDetector,
            JsonRequestBodyPayloadInspector jsonBodyInspector
    ) {
        this.requestLogService = requestLogService;
        this.properties = properties;
        this.payloadProperties = payloadProperties;
        this.payloadSignatureDetector = payloadSignatureDetector;
        this.jsonBodyInspector = jsonBodyInspector;
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        return !properties.isEnabled() || properties.getExcludedPaths().contains(request.getRequestURI());
    }

    @Override
    protected boolean shouldNotFilterAsyncDispatch() {
        return true;
    }

    @Override
    protected boolean shouldNotFilterErrorDispatch() {
        return true;
    }

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain
    ) throws ServletException, IOException {
        Instant requestedAt = Instant.now();
        long startNanos = System.nanoTime();
        OverflowTrackingContentCachingRequestWrapper cachingRequest = wrapInspectableJsonBody(request);
        HttpServletRequest downstreamRequest = cachingRequest == null ? request : cachingRequest;

        try {
            filterChain.doFilter(downstreamRequest, response);
        } finally {
            long durationMs = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - startNanos);
            List<PayloadDetectionFinding> findings = detectPayloads(request, cachingRequest);
            RequestLogData data = new RequestLogData(
                    requestedAt,
                    request.getRemoteAddr(),
                    request.getMethod(),
                    requestPathForStorage(request, response.getStatus(), findings),
                    response.getStatus(),
                    durationMs
            );

            try {
                requestLogService.save(data, findings);
            } catch (RuntimeException exception) {
                logger.error("Unable to persist API request metadata; the original response is unchanged");
            }
        }
    }

    private List<PayloadDetectionFinding> detectPayloads(
            HttpServletRequest request,
            OverflowTrackingContentCachingRequestWrapper cachingRequest
    ) {
        Set<PayloadDetectionFinding> findings = new LinkedHashSet<>();
        addQueryFindings(request, findings);
        addPathFindings(request, findings);
        addJsonBodyFindings(cachingRequest, findings);
        return List.copyOf(findings);
    }

    private void addQueryFindings(HttpServletRequest request, Set<PayloadDetectionFinding> findings) {
        try {
            findings.addAll(payloadSignatureDetector.detect(request.getQueryString()));
        } catch (RuntimeException detectionFailure) {
            logger.error("Query-payload inspection failed; request logging will continue without findings");
        }
    }

    private void addPathFindings(HttpServletRequest request, Set<PayloadDetectionFinding> findings) {
        try {
            findings.addAll(payloadSignatureDetector.detectPath(request.getRequestURI()));
        } catch (RuntimeException detectionFailure) {
            logger.error("Request-path inspection failed; request logging will continue without path findings");
        }
    }

    private void addJsonBodyFindings(
            OverflowTrackingContentCachingRequestWrapper cachingRequest,
            Set<PayloadDetectionFinding> findings
    ) {
        if (cachingRequest == null || cachingRequest.isOverflowed()) {
            return;
        }

        byte[] cachedBody = cachingRequest.getContentAsByteArray();
        if (cachedBody.length == 0 || cachedBody.length != cachingRequest.getContentLengthLong()) {
            return;
        }

        try {
            findings.addAll(jsonBodyInspector.inspect(cachedBody));
        } catch (RuntimeException detectionFailure) {
            logger.error("JSON-body inspection failed; request logging will continue without body findings");
        }
    }

    private OverflowTrackingContentCachingRequestWrapper wrapInspectableJsonBody(HttpServletRequest request) {
        if (!payloadProperties.isEnabled()) {
            return null;
        }

        long contentLength = request.getContentLengthLong();
        if (contentLength <= 0 || contentLength > payloadProperties.getMaxBodyCacheBytes()) {
            return null;
        }

        String contentEncoding = request.getHeader("Content-Encoding");
        if (contentEncoding != null && !contentEncoding.isBlank()
                && !"identity".equalsIgnoreCase(contentEncoding.trim())) {
            return null;
        }

        MediaType mediaType;
        try {
            mediaType = MediaType.parseMediaType(request.getContentType());
        } catch (InvalidMediaTypeException invalidMediaType) {
            return null;
        }
        if (!MediaType.APPLICATION_JSON.getType().equals(mediaType.getType())
                || !MediaType.APPLICATION_JSON.getSubtype().equals(mediaType.getSubtype())) {
            return null;
        }
        if (mediaType.getCharset() != null && !StandardCharsets.UTF_8.equals(mediaType.getCharset())) {
            return null;
        }

        return new OverflowTrackingContentCachingRequestWrapper(
                request, payloadProperties.getMaxBodyCacheBytes());
    }

    private String requestPathForStorage(
            HttpServletRequest request,
            int responseStatus,
            List<PayloadDetectionFinding> findings
    ) {
        Object routeTemplate = request.getAttribute(HandlerMapping.BEST_MATCHING_PATTERN_ATTRIBUTE);
        if (routeTemplate != null && !routeTemplate.toString().isBlank()
                && !isMissingStaticResource(request, responseStatus)) {
            return routeTemplate.toString();
        }
        boolean suspiciousPath = findings.stream()
                .anyMatch(finding -> finding.inputLocation() == InputLocation.REQUEST_PATH);
        return suspiciousPath ? REDACTED_SUSPICIOUS_PATH : request.getRequestURI();
    }

    private boolean isMissingStaticResource(HttpServletRequest request, int responseStatus) {
        Object handler = request.getAttribute(HandlerMapping.BEST_MATCHING_HANDLER_ATTRIBUTE);
        return responseStatus == HttpServletResponse.SC_NOT_FOUND
                && handler instanceof ResourceHttpRequestHandler;
    }

    private static final class OverflowTrackingContentCachingRequestWrapper
            extends ContentCachingRequestWrapper {

        private boolean overflowed;

        private OverflowTrackingContentCachingRequestWrapper(HttpServletRequest request, int contentCacheLimit) {
            super(request, contentCacheLimit);
        }

        @Override
        protected void handleContentOverflow(int contentCacheLimit) {
            overflowed = true;
        }

        private boolean isOverflowed() {
            return overflowed;
        }
    }
}
