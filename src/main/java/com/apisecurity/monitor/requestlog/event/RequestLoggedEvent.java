package com.apisecurity.monitor.requestlog.event;

import java.time.Instant;

public record RequestLoggedEvent(
        Long requestLogId,
        Instant requestedAt,
        String clientIp
) {
}
