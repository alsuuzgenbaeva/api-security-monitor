package com.apisecurity.monitor.securityevent.repository;

import com.apisecurity.monitor.securityevent.model.SecurityEvent;
import com.apisecurity.monitor.securityevent.model.SecurityEventType;
import org.springframework.data.jpa.repository.JpaRepository;

import java.time.Instant;

public interface SecurityEventRepository extends JpaRepository<SecurityEvent, Long> {

    boolean existsByDeduplicationKey(String deduplicationKey);

    boolean existsByEventTypeAndClientIpAndOccurredAtGreaterThanEqual(
            SecurityEventType eventType,
            String clientIp,
            Instant cutoff
    );
}
