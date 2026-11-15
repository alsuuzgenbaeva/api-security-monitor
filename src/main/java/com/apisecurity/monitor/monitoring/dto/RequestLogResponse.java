package com.apisecurity.monitor.monitoring.dto;

import java.time.Instant;

public record RequestLogResponse(
        Long id,
        Instant requestedAt,
        String clientIp,
        String httpMethod,
        String requestPath,
        int responseStatus,
        long durationMs
) {
}
