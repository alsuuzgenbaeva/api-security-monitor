package com.apisecurity.monitor.securityevent.model;

import java.time.Instant;

public record SecurityEventData(
        SecurityEventType eventType,
        RiskLevel riskLevel,
        Instant occurredAt,
        String clientIp,
        String detectionReason,
        Long sourceRequestLogId,
        long observedRequestCount,
        int configuredThreshold,
        long windowSeconds,
        Long observedDistinctPathCount,
        Integer configuredDistinctPathThreshold,
        Long observedClientErrorCount,
        Integer configuredClientErrorRatePercent
) {

    public SecurityEventData(
            SecurityEventType eventType,
            RiskLevel riskLevel,
            Instant occurredAt,
            String clientIp,
            String detectionReason,
            Long sourceRequestLogId,
            long observedRequestCount,
            int configuredThreshold,
            long windowSeconds
    ) {
        this(
                eventType,
                riskLevel,
                occurredAt,
                clientIp,
                detectionReason,
                sourceRequestLogId,
                observedRequestCount,
                configuredThreshold,
                windowSeconds,
                null,
                null,
                null,
                null);
    }
}
