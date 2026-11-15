package com.apisecurity.monitor.requestlog.repository;

import com.apisecurity.monitor.requestlog.model.ApiRequestLog;
import org.springframework.data.jpa.repository.JpaRepository;

import java.time.Instant;

public interface ApiRequestLogRepository extends JpaRepository<ApiRequestLog, Long> {

    long countByClientIpAndRequestedAtGreaterThanEqual(String clientIp, Instant windowStart);

    long countByRequestedAtGreaterThanEqual(Instant cutoff);

    long countByResponseStatusGreaterThanEqualAndRequestedAtGreaterThanEqual(int responseStatus, Instant cutoff);
}
