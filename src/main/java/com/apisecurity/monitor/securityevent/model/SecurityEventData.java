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
        long windowSeconds
) {
}
