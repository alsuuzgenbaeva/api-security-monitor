package com.apisecurity.monitor.anomaly.endpointscanning.service;

import com.apisecurity.monitor.anomaly.endpointscanning.config.EndpointScanningDetectionProperties;
import com.apisecurity.monitor.requestlog.event.RequestLoggedEvent;
import com.apisecurity.monitor.requestlog.repository.ApiRequestLogRepository;
import com.apisecurity.monitor.requestlog.repository.EndpointScanningWindowStatistics;
import com.apisecurity.monitor.securityevent.model.RiskLevel;
import com.apisecurity.monitor.securityevent.model.SecurityEventData;
import com.apisecurity.monitor.securityevent.model.SecurityEventType;
import com.apisecurity.monitor.securityevent.service.SecurityEventService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.event.TransactionPhase;
import org.springframework.transaction.event.TransactionalEventListener;

import java.time.Instant;

@Service
public class EndpointScanningDetector {

    private static final Logger logger = LoggerFactory.getLogger(EndpointScanningDetector.class);
    private static final int NOT_FOUND_STATUS = 404;

    private final ApiRequestLogRepository requestLogRepository;
    private final SecurityEventService securityEventService;
    private final EndpointScanningDetectionProperties properties;

    public EndpointScanningDetector(
            ApiRequestLogRepository requestLogRepository,
            SecurityEventService securityEventService,
            EndpointScanningDetectionProperties properties
    ) {
        this.requestLogRepository = requestLogRepository;
        this.securityEventService = securityEventService;
        this.properties = properties;
    }

    @TransactionalEventListener(phase = TransactionPhase.AFTER_COMMIT)
    public void onRequestLogged(RequestLoggedEvent event) {
        try {
            detect(event);
        } catch (RuntimeException detectionFailure) {
            logger.error("Endpoint-scanning detection failed; the original response is unchanged");
        }
    }

    void detect(RequestLoggedEvent event) {
        if (!properties.isEnabled() || event.responseStatus() != NOT_FOUND_STATUS) {
            return;
        }

        Instant windowStart = event.requestedAt().minus(properties.getWindow());
        EndpointScanningWindowStatistics statistics = requestLogRepository
                .summarizeEndpointScanningWindow(event.clientIp(), windowStart, event.requestedAt());
        long unsuccessfulRequests = statistics.getUnsuccessfulRequestCount();
        long distinctPaths = statistics.getDistinctPathCount();
        if (unsuccessfulRequests < properties.getMinimumUnsuccessfulRequests()
                || distinctPaths < properties.getDistinctPathThreshold()) {
            return;
        }

        String reason = ("Potential endpoint-scanning indicator: observed %d HTTP 404 requests across "
                + "%d distinct stored paths from one client IP within %d seconds; configured minima are "
                + "%d unsuccessful requests and %d distinct paths.")
                .formatted(
                        unsuccessfulRequests,
                        distinctPaths,
                        properties.getWindow().getSeconds(),
                        properties.getMinimumUnsuccessfulRequests(),
                        properties.getDistinctPathThreshold());
        SecurityEventData eventData = new SecurityEventData(
                SecurityEventType.ENDPOINT_SCANNING,
                RiskLevel.MEDIUM,
                event.requestedAt(),
                event.clientIp(),
                reason,
                event.requestLogId(),
                unsuccessfulRequests,
                properties.getMinimumUnsuccessfulRequests(),
                properties.getWindow().getSeconds(),
                distinctPaths,
                properties.getDistinctPathThreshold(),
                null,
                null
        );
        securityEventService.createIfNotSuppressed(eventData, properties.getSuppressionPeriod());
    }
}
