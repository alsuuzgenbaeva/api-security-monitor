package com.apisecurity.monitor.requestlog.model;

import java.time.Instant;

public record RequestLogData(
        Instant requestedAt,
        String clientIp,
        String httpMethod,
        String requestPath,
        int responseStatus,
        long durationMs
) {
}
