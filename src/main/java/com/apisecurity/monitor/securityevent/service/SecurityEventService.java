package com.apisecurity.monitor.securityevent.service;

import com.apisecurity.monitor.securityevent.model.SecurityEventData;
import com.apisecurity.monitor.securityevent.repository.SecurityEventRepository;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Duration;
import java.time.Instant;
import java.util.Objects;

@Service
public class SecurityEventService {

    private final SecurityEventRepository repository;
    private final SecurityEventWriter writer;

    public SecurityEventService(SecurityEventRepository repository, SecurityEventWriter writer) {
        this.repository = repository;
        this.writer = writer;
    }

    @Transactional(readOnly = true)
    public boolean createIfNotSuppressed(SecurityEventData data, Duration suppressionPeriod) {
        Objects.requireNonNull(data, "Security event data must not be null");
        Objects.requireNonNull(suppressionPeriod, "Suppression period must not be null");
        long suppressionSeconds = suppressionPeriod.getSeconds();
        if (suppressionSeconds < 1) {
            throw new IllegalArgumentException("Suppression period must be at least one second");
        }

        Instant cutoff = data.occurredAt().minus(suppressionPeriod);
        if (repository.existsByEventTypeAndClientIpAndOccurredAtGreaterThanEqual(
                data.eventType(), data.clientIp(), cutoff)) {
            return false;
        }

        String deduplicationKey = createDeduplicationKey(data, suppressionSeconds);
        try {
            writer.insert(data, deduplicationKey);
            return true;
        } catch (DataIntegrityViolationException persistenceFailure) {
            if (repository.existsByDeduplicationKey(deduplicationKey)) {
                return false;
            }
            throw persistenceFailure;
        }
    }

    private String createDeduplicationKey(SecurityEventData data, long suppressionSeconds) {
        long timeBucket = Math.floorDiv(data.occurredAt().getEpochSecond(), suppressionSeconds);
        return data.eventType() + "|" + data.clientIp() + "|" + timeBucket;
    }
}
