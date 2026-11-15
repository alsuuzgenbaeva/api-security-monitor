package com.apisecurity.monitor.monitoring.dto;

import java.time.Instant;

public record MonitoringSummaryResponse(
        long totalRequests,
        long requestsLast24Hours,
        long errorsLast24Hours,
        long totalSecurityEvents,
        long securityEventsLast24Hours,
        Instant generatedAt
) {
}
