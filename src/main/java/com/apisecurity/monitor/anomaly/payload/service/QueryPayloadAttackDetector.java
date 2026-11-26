package com.apisecurity.monitor.anomaly.payload.service;

import com.apisecurity.monitor.anomaly.payload.config.QueryPayloadDetectionProperties;
import com.apisecurity.monitor.anomaly.payload.model.PayloadDetectionFinding;
import com.apisecurity.monitor.requestlog.event.RequestLoggedEvent;
import com.apisecurity.monitor.securityevent.model.RiskLevel;
import com.apisecurity.monitor.securityevent.model.SecurityEventData;
import com.apisecurity.monitor.securityevent.model.SecurityEventType;
import com.apisecurity.monitor.securityevent.service.SecurityEventService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.event.TransactionPhase;
import org.springframework.transaction.event.TransactionalEventListener;

import java.util.EnumMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@Service
public class QueryPayloadAttackDetector {

    private static final Logger logger = LoggerFactory.getLogger(QueryPayloadAttackDetector.class);

    private final SecurityEventService securityEventService;
    private final QueryPayloadDetectionProperties properties;

    public QueryPayloadAttackDetector(
            SecurityEventService securityEventService,
            QueryPayloadDetectionProperties properties
    ) {
        this.securityEventService = securityEventService;
        this.properties = properties;
    }

    @TransactionalEventListener(phase = TransactionPhase.AFTER_COMMIT)
    public void onRequestLogged(RequestLoggedEvent event) {
        try {
            detect(event);
        } catch (RuntimeException detectionFailure) {
            logger.error("Query-payload event creation failed; the original response is unchanged");
        }
    }

    void detect(RequestLoggedEvent event) {
        if (!properties.isEnabled() || event.payloadFindings().isEmpty()) {
            return;
        }

        Map<SecurityEventType, List<PayloadDetectionFinding>> groupedFindings = event.payloadFindings().stream()
                .collect(Collectors.groupingBy(
                        PayloadDetectionFinding::eventType,
                        () -> new EnumMap<>(SecurityEventType.class),
                        Collectors.toList()));

        groupedFindings.forEach((eventType, findings) -> {
            try {
                createEvent(event, eventType, findings);
            } catch (RuntimeException eventCreationFailure) {
                logger.error(
                        "Query-payload event creation failed for {}; other event types will continue",
                        eventType);
            }
        });
    }

    private void createEvent(
            RequestLoggedEvent requestEvent,
            SecurityEventType eventType,
            List<PayloadDetectionFinding> findings
    ) {
        String signatureIdentifiers = findings.stream()
                .map(finding -> finding.signatureIdentifier().name())
                .distinct()
                .sorted()
                .collect(Collectors.joining(", "));
        String reason = "Potential %s indicator detected; location: QUERY_PARAMETER; signatures: %s."
                .formatted(displayName(eventType), signatureIdentifiers);

        SecurityEventData eventData = new SecurityEventData(
                eventType,
                RiskLevel.HIGH,
                requestEvent.requestedAt(),
                requestEvent.clientIp(),
                reason,
                requestEvent.requestLogId(),
                findings.size(),
                1,
                0
        );
        securityEventService.createIfNotSuppressed(eventData, properties.getSuppressionPeriod());
    }

    private String displayName(SecurityEventType eventType) {
        return switch (eventType) {
            case XSS_ATTEMPT -> "XSS attempt";
            case SQL_INJECTION_ATTEMPT -> "SQL injection attempt";
            case EXCESSIVE_REQUESTS -> throw new IllegalArgumentException("Unsupported query-payload event type");
        };
    }
}
