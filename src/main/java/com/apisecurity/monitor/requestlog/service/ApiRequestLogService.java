package com.apisecurity.monitor.requestlog.service;

import com.apisecurity.monitor.requestlog.event.RequestLoggedEvent;
import com.apisecurity.monitor.requestlog.model.ApiRequestLog;
import com.apisecurity.monitor.requestlog.model.RequestLogData;
import com.apisecurity.monitor.requestlog.repository.ApiRequestLogRepository;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import java.util.Objects;

@Service
public class ApiRequestLogService {

    private static final int MAX_IP_LENGTH = 45;
    private static final int MAX_METHOD_LENGTH = 16;
    private static final int MAX_PATH_LENGTH = 2048;

    private final ApiRequestLogRepository repository;
    private final ApplicationEventPublisher eventPublisher;

    public ApiRequestLogService(ApiRequestLogRepository repository, ApplicationEventPublisher eventPublisher) {
        this.repository = repository;
        this.eventPublisher = eventPublisher;
    }

    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void save(RequestLogData data) {
        Objects.requireNonNull(data, "Request log data must not be null");

        RequestLogData safeData = new RequestLogData(
                Objects.requireNonNull(data.requestedAt(), "Request timestamp must not be null"),
                truncate(Objects.requireNonNull(data.clientIp(), "Client IP must not be null"), MAX_IP_LENGTH),
                truncate(Objects.requireNonNull(data.httpMethod(), "HTTP method must not be null"), MAX_METHOD_LENGTH),
                truncate(Objects.requireNonNull(data.requestPath(), "Request path must not be null"), MAX_PATH_LENGTH),
                data.responseStatus(),
                Math.max(0, data.durationMs())
        );

        ApiRequestLog savedLog = repository.saveAndFlush(new ApiRequestLog(safeData));
        eventPublisher.publishEvent(new RequestLoggedEvent(
                savedLog.getId(),
                savedLog.getRequestedAt(),
                savedLog.getClientIp()
        ));
    }

    private String truncate(String value, int maximumLength) {
        return value.length() <= maximumLength ? value : value.substring(0, maximumLength);
    }
}
