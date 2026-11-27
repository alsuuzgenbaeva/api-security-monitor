package com.apisecurity.monitor.requestlog.repository;

import com.apisecurity.monitor.requestlog.model.ApiRequestLog;
import com.apisecurity.monitor.requestlog.model.RequestLogData;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.data.jpa.test.autoconfigure.DataJpaTest;
import org.springframework.boot.jdbc.test.autoconfigure.AutoConfigureTestDatabase;

import java.time.Instant;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

@DataJpaTest
@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.NONE)
class ApiRequestLogRepositoryPostgresIT {

    private static final Instant WINDOW_START = Instant.parse("2026-11-27T10:00:00Z");
    private static final Instant WINDOW_END = Instant.parse("2026-11-27T10:01:00Z");
    private static final String CLIENT_IP = "192.0.2.10";

    @Autowired
    private ApiRequestLogRepository repository;

    @Test
    void aggregatesStatusesDistinctStoredPathsAndInclusiveTimeBoundaries() {
        repository.saveAllAndFlush(List.of(
                log(WINDOW_START, CLIENT_IP, "/missing/a", 404),
                log(WINDOW_START.plusSeconds(5), CLIENT_IP, "/missing/a", 404),
                log(WINDOW_START.plusSeconds(10), CLIENT_IP, "/missing/b", 404),
                log(WINDOW_START.plusSeconds(20), CLIENT_IP, "/missing/c", 404),
                log(WINDOW_START.plusSeconds(30), CLIENT_IP, "/missing/d", 404),
                log(WINDOW_START.plusSeconds(40), CLIENT_IP, "/missing/e", 404),
                log(WINDOW_START.plusSeconds(50), CLIENT_IP, "/missing/e", 404),
                log(WINDOW_END, CLIENT_IP, "/missing/a", 404),
                log(WINDOW_START.plusSeconds(15), CLIENT_IP, "/login-required", 401),
                log(WINDOW_START.plusSeconds(25), CLIENT_IP, "/csrf-rejected", 403),
                log(WINDOW_START.plusSeconds(35), CLIENT_IP, "/rate-limited", 429),
                log(WINDOW_START.plusSeconds(45), CLIENT_IP, "/server-failure", 500),
                log(WINDOW_START.plusSeconds(55), CLIENT_IP, "/healthy", 200),
                log(WINDOW_START.minusNanos(1_000), CLIENT_IP, "/outside-before", 404),
                log(WINDOW_END.plusNanos(1_000), CLIENT_IP, "/outside-after", 404),
                log(WINDOW_START.plusSeconds(30), "192.0.2.11", "/other-client", 404)
        ));

        EndpointScanningWindowStatistics endpointStatistics = repository
                .summarizeEndpointScanningWindow(CLIENT_IP, WINDOW_START, WINDOW_END);
        ErrorRateWindowStatistics errorStatistics = repository
                .summarizeErrorRateWindow(CLIENT_IP, WINDOW_START, WINDOW_END);

        assertThat(endpointStatistics.getUnsuccessfulRequestCount()).isEqualTo(8);
        assertThat(endpointStatistics.getDistinctPathCount()).isEqualTo(5);
        assertThat(errorStatistics.getTotalRequestCount()).isEqualTo(13);
        assertThat(errorStatistics.getClientErrorCount()).isEqualTo(8);
        assertThat(errorStatistics.getServerErrorCount()).isEqualTo(1);
    }

    private ApiRequestLog log(Instant requestedAt, String clientIp, String path, int status) {
        return new ApiRequestLog(new RequestLogData(
                requestedAt,
                clientIp,
                "GET",
                path,
                status,
                1
        ));
    }
}
