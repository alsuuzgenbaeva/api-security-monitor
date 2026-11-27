package com.apisecurity.monitor.requestlog.event;

import com.apisecurity.monitor.anomaly.payload.model.PayloadDetectionFinding;

import java.time.Instant;
import java.util.List;

public record RequestLoggedEvent(
        Long requestLogId,
        Instant requestedAt,
        String clientIp,
        int responseStatus,
        List<PayloadDetectionFinding> payloadFindings
) {

    public RequestLoggedEvent {
        payloadFindings = List.copyOf(payloadFindings);
    }

    public RequestLoggedEvent(Long requestLogId, Instant requestedAt, String clientIp) {
        this(requestLogId, requestedAt, clientIp, 0, List.of());
    }

    public RequestLoggedEvent(
            Long requestLogId,
            Instant requestedAt,
            String clientIp,
            List<PayloadDetectionFinding> payloadFindings
    ) {
        this(requestLogId, requestedAt, clientIp, 0, payloadFindings);
    }
}
