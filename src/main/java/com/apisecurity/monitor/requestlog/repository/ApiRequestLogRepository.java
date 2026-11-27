package com.apisecurity.monitor.requestlog.repository;

import com.apisecurity.monitor.requestlog.model.ApiRequestLog;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.Instant;

public interface ApiRequestLogRepository extends JpaRepository<ApiRequestLog, Long> {

    long countByClientIpAndRequestedAtGreaterThanEqual(String clientIp, Instant windowStart);

    long countByRequestedAtGreaterThanEqual(Instant cutoff);

    long countByResponseStatusGreaterThanEqualAndRequestedAtGreaterThanEqual(int responseStatus, Instant cutoff);

    @Query("""
            select count(requestLog.id) as unsuccessfulRequestCount,
                   count(distinct requestLog.requestPath) as distinctPathCount
            from ApiRequestLog requestLog
            where requestLog.clientIp = :clientIp
              and requestLog.requestedAt >= :windowStart
              and requestLog.requestedAt <= :windowEnd
              and requestLog.responseStatus = 404
            """)
    EndpointScanningWindowStatistics summarizeEndpointScanningWindow(
            @Param("clientIp") String clientIp,
            @Param("windowStart") Instant windowStart,
            @Param("windowEnd") Instant windowEnd
    );

    @Query("""
            select count(requestLog.id) as totalRequestCount,
                   coalesce(sum(case
                       when requestLog.responseStatus between 400 and 499
                            and requestLog.responseStatus not in (401, 403, 429)
                       then 1 else 0 end), 0) as clientErrorCount,
                   coalesce(sum(case
                       when requestLog.responseStatus between 500 and 599
                       then 1 else 0 end), 0) as serverErrorCount
            from ApiRequestLog requestLog
            where requestLog.clientIp = :clientIp
              and requestLog.requestedAt >= :windowStart
              and requestLog.requestedAt <= :windowEnd
            """)
    ErrorRateWindowStatistics summarizeErrorRateWindow(
            @Param("clientIp") String clientIp,
            @Param("windowStart") Instant windowStart,
            @Param("windowEnd") Instant windowEnd
    );
}
