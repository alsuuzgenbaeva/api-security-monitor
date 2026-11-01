package com.apisecurity.monitor.anomaly.excessiverequests.service;

import com.apisecurity.monitor.anomaly.excessiverequests.config.ExcessiveRequestRuleProperties;
import com.apisecurity.monitor.requestlog.event.RequestLoggedEvent;
import com.apisecurity.monitor.requestlog.repository.ApiRequestLogRepository;
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
public class ExcessiveRequestDetector {

    private static final Logger logger = LoggerFactory.getLogger(ExcessiveRequestDetector.class);

    private final ApiRequestLogRepository requestLogRepository;
    private final SecurityEventService securityEventService;
    private final ExcessiveRequestRuleProperties properties;

    public ExcessiveRequestDetector(
            ApiRequestLogRepository requestLogRepository,
            SecurityEventService securityEventService,
            ExcessiveRequestRuleProperties properties
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
            logger.error("Excessive-request detection failed; the original response is unchanged");
        }
    }

    void detect(RequestLoggedEvent event) {
        if (!properties.isEnabled()) {
            return;
        }

        Instant windowStart = event.requestedAt().minus(properties.getWindow());
        long observedCount = requestLogRepository
                .countByClientIpAndRequestedAtGreaterThanEqual(event.clientIp(), windowStart);
        if (observedCount < properties.getThreshold()) {
            return;
        }

        String reason = "Observed %d requests from one client IP within %d seconds; configured threshold is %d."
                .formatted(observedCount, properties.getWindow().getSeconds(), properties.getThreshold());
        SecurityEventData eventData = new SecurityEventData(
                SecurityEventType.EXCESSIVE_REQUESTS,
                RiskLevel.MEDIUM,
                event.requestedAt(),
                event.clientIp(),
                reason,
                event.requestLogId(),
                observedCount,
                properties.getThreshold(),
                properties.getWindow().getSeconds()
        );
        securityEventService.createIfNotSuppressed(eventData, properties.getSuppressionPeriod());
    }
}
