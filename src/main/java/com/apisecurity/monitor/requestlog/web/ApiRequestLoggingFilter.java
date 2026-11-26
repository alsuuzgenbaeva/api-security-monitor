package com.apisecurity.monitor.requestlog.web;

import com.apisecurity.monitor.anomaly.payload.model.PayloadDetectionFinding;
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
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.time.Instant;
import java.util.List;
import java.util.concurrent.TimeUnit;

@Component
public class ApiRequestLoggingFilter extends OncePerRequestFilter {

    private static final Logger logger = LoggerFactory.getLogger(ApiRequestLoggingFilter.class);

    private final ApiRequestLogService requestLogService;
    private final RequestLoggingProperties properties;
    private final PayloadSignatureDetector payloadSignatureDetector;

    public ApiRequestLoggingFilter(
            ApiRequestLogService requestLogService,
            RequestLoggingProperties properties,
            PayloadSignatureDetector payloadSignatureDetector
    ) {
        this.requestLogService = requestLogService;
        this.properties = properties;
        this.payloadSignatureDetector = payloadSignatureDetector;
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

        try {
            filterChain.doFilter(request, response);
        } finally {
            long durationMs = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - startNanos);
            List<PayloadDetectionFinding> findings = detectQueryPayload(request);
            RequestLogData data = new RequestLogData(
                    requestedAt,
                    request.getRemoteAddr(),
                    request.getMethod(),
                    request.getRequestURI(),
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

    private List<PayloadDetectionFinding> detectQueryPayload(HttpServletRequest request) {
        try {
            return payloadSignatureDetector.detect(request.getQueryString());
        } catch (RuntimeException detectionFailure) {
            logger.error("Query-payload inspection failed; request logging will continue without findings");
            return List.of();
        }
    }
}
