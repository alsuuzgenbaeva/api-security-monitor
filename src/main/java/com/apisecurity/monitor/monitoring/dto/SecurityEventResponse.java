package com.apisecurity.monitor.monitoring.dto;

import com.apisecurity.monitor.securityevent.model.RiskLevel;
import com.apisecurity.monitor.securityevent.model.SecurityEventType;

import java.time.Instant;

public record SecurityEventResponse(
        Long id,
        SecurityEventType eventType,
        RiskLevel riskLevel,
        Instant occurredAt,
        String clientIp,
        String detectionReason,
        long observedRequestCount,
        int configuredThreshold,
        long windowSeconds,
        Long observedDistinctPathCount,
        Integer configuredDistinctPathThreshold,
        Long observedClientErrorCount,
        Integer configuredClientErrorRatePercent
) {
}
