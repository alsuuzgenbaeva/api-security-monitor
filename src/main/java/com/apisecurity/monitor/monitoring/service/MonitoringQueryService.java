package com.apisecurity.monitor.monitoring.service;

import com.apisecurity.monitor.monitoring.dto.MonitoringSummaryResponse;
import com.apisecurity.monitor.monitoring.dto.PagedResponse;
import com.apisecurity.monitor.monitoring.dto.RequestLogResponse;
import com.apisecurity.monitor.monitoring.dto.SecurityEventResponse;
import com.apisecurity.monitor.requestlog.model.ApiRequestLog;
import com.apisecurity.monitor.requestlog.repository.ApiRequestLogRepository;
import com.apisecurity.monitor.securityevent.model.SecurityEvent;
import com.apisecurity.monitor.securityevent.repository.SecurityEventRepository;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;

@Service
@Transactional(readOnly = true)
public class MonitoringQueryService {

    static final int DEFAULT_PAGE_SIZE = 20;
    static final int MAX_PAGE_SIZE = 100;
    private static final Duration RECENT_PERIOD = Duration.ofHours(24);

    private final ApiRequestLogRepository requestLogRepository;
    private final SecurityEventRepository securityEventRepository;
    private final Clock clock;

    public MonitoringQueryService(
            ApiRequestLogRepository requestLogRepository,
            SecurityEventRepository securityEventRepository,
            Clock clock
    ) {
        this.requestLogRepository = requestLogRepository;
        this.securityEventRepository = securityEventRepository;
        this.clock = clock;
    }

    public MonitoringSummaryResponse getSummary() {
        Instant generatedAt = clock.instant();
        Instant recentCutoff = generatedAt.minus(RECENT_PERIOD);
        return new MonitoringSummaryResponse(
                requestLogRepository.count(),
                requestLogRepository.countByRequestedAtGreaterThanEqual(recentCutoff),
                requestLogRepository.countByResponseStatusGreaterThanEqualAndRequestedAtGreaterThanEqual(
                        400, recentCutoff),
                securityEventRepository.count(),
                securityEventRepository.countByOccurredAtGreaterThanEqual(recentCutoff),
                generatedAt
        );
    }

    public PagedResponse<RequestLogResponse> getRequests(int page, int size) {
        Pageable pageable = recentFirstPage(page, size, "requestedAt");
        Page<RequestLogResponse> result = requestLogRepository.findAll(pageable).map(this::toResponse);
        return PagedResponse.from(result);
    }

    public PagedResponse<SecurityEventResponse> getEvents(int page, int size) {
        Pageable pageable = recentFirstPage(page, size, "occurredAt");
        Page<SecurityEventResponse> result = securityEventRepository.findAll(pageable).map(this::toResponse);
        return PagedResponse.from(result);
    }

    private Pageable recentFirstPage(int requestedPage, int requestedSize, String timestampProperty) {
        int page = Math.max(0, requestedPage);
        int size = requestedSize < 1 ? DEFAULT_PAGE_SIZE : Math.min(requestedSize, MAX_PAGE_SIZE);
        return PageRequest.of(page, size, Sort.by(Sort.Direction.DESC, timestampProperty));
    }

    private RequestLogResponse toResponse(ApiRequestLog log) {
        return new RequestLogResponse(
                log.getId(),
                log.getRequestedAt(),
                log.getClientIp(),
                log.getHttpMethod(),
                withoutQueryString(log.getRequestPath()),
                log.getResponseStatus(),
                log.getDurationMs()
        );
    }

    private String withoutQueryString(String path) {
        int queryStart = path.indexOf('?');
        return queryStart < 0 ? path : path.substring(0, queryStart);
    }

    private SecurityEventResponse toResponse(SecurityEvent event) {
        return new SecurityEventResponse(
                event.getId(),
                event.getEventType(),
                event.getRiskLevel(),
                event.getOccurredAt(),
                event.getClientIp(),
                event.getDetectionReason(),
                event.getObservedRequestCount(),
                event.getConfiguredThreshold(),
                event.getWindowSeconds()
        );
    }
}
