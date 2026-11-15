package com.apisecurity.monitor.monitoring.service;

import com.apisecurity.monitor.monitoring.dto.MonitoringSummaryResponse;
import com.apisecurity.monitor.monitoring.dto.PagedResponse;
import com.apisecurity.monitor.monitoring.dto.RequestLogResponse;
import com.apisecurity.monitor.monitoring.dto.SecurityEventResponse;
import com.apisecurity.monitor.requestlog.model.ApiRequestLog;
import com.apisecurity.monitor.requestlog.model.RequestLogData;
import com.apisecurity.monitor.requestlog.repository.ApiRequestLogRepository;
import com.apisecurity.monitor.securityevent.model.RiskLevel;
import com.apisecurity.monitor.securityevent.model.SecurityEvent;
import com.apisecurity.monitor.securityevent.model.SecurityEventData;
import com.apisecurity.monitor.securityevent.model.SecurityEventType;
import com.apisecurity.monitor.securityevent.repository.SecurityEventRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.test.util.ReflectionTestUtils;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class MonitoringQueryServiceTest {

    private static final Instant NOW = Instant.parse("2026-11-16T08:00:00Z");

    @Mock
    private ApiRequestLogRepository requestLogRepository;

    @Mock
    private SecurityEventRepository securityEventRepository;

    private MonitoringQueryService service;

    @BeforeEach
    void setUp() {
        service = new MonitoringQueryService(
                requestLogRepository,
                securityEventRepository,
                Clock.fixed(NOW, ZoneOffset.UTC)
        );
    }

    @Test
    void calculatesSummaryForRollingTwentyFourHours() {
        Instant cutoff = NOW.minusSeconds(24 * 60 * 60);
        when(requestLogRepository.count()).thenReturn(120L);
        when(requestLogRepository.countByRequestedAtGreaterThanEqual(cutoff)).thenReturn(45L);
        when(requestLogRepository.countByResponseStatusGreaterThanEqualAndRequestedAtGreaterThanEqual(400, cutoff))
                .thenReturn(3L);
        when(securityEventRepository.count()).thenReturn(7L);
        when(securityEventRepository.countByOccurredAtGreaterThanEqual(cutoff)).thenReturn(2L);

        MonitoringSummaryResponse summary = service.getSummary();

        assertThat(summary).isEqualTo(new MonitoringSummaryResponse(120, 45, 3, 7, 2, NOW));
    }

    @Test
    void mapsRequestsAndCapsPageSizeWithNewestFirstOrdering() {
        ApiRequestLog log = new ApiRequestLog(new RequestLogData(
                NOW.minusSeconds(5),
                "127.0.0.1",
                "GET",
                "/api/test?token=must-not-be-exposed",
                200,
                12
        ));
        ReflectionTestUtils.setField(log, "id", 41L);
        when(requestLogRepository.findAll(any(Pageable.class)))
                .thenReturn(new PageImpl<>(List.of(log)));

        PagedResponse<RequestLogResponse> response = service.getRequests(2, 1_000);

        ArgumentCaptor<Pageable> captor = ArgumentCaptor.forClass(Pageable.class);
        verify(requestLogRepository).findAll(captor.capture());
        Pageable pageable = captor.getValue();
        assertThat(pageable.getPageNumber()).isEqualTo(2);
        assertThat(pageable.getPageSize()).isEqualTo(100);
        assertThat(pageable.getSort().getOrderFor("requestedAt").getDirection()).isEqualTo(Sort.Direction.DESC);

        assertThat(response.content()).containsExactly(new RequestLogResponse(
                41L, NOW.minusSeconds(5), "127.0.0.1", "GET", "/api/test", 200, 12));
    }

    @Test
    void mapsEventsAndNormalizesInvalidPagination() {
        SecurityEvent event = new SecurityEvent(new SecurityEventData(
                SecurityEventType.EXCESSIVE_REQUESTS,
                RiskLevel.MEDIUM,
                NOW.minusSeconds(10),
                "127.0.0.1",
                "Observed five requests in ten seconds.",
                41L,
                5,
                5,
                10
        ), "internal-deduplication-key");
        ReflectionTestUtils.setField(event, "id", 9L);
        when(securityEventRepository.findAll(any(Pageable.class)))
                .thenReturn(new PageImpl<>(List.of(event)));

        PagedResponse<SecurityEventResponse> response = service.getEvents(-4, 0);

        ArgumentCaptor<Pageable> captor = ArgumentCaptor.forClass(Pageable.class);
        verify(securityEventRepository).findAll(captor.capture());
        Pageable pageable = captor.getValue();
        assertThat(pageable.getPageNumber()).isZero();
        assertThat(pageable.getPageSize()).isEqualTo(20);
        assertThat(pageable.getSort().getOrderFor("occurredAt").getDirection()).isEqualTo(Sort.Direction.DESC);

        assertThat(response.content()).containsExactly(new SecurityEventResponse(
                9L,
                SecurityEventType.EXCESSIVE_REQUESTS,
                RiskLevel.MEDIUM,
                NOW.minusSeconds(10),
                "127.0.0.1",
                "Observed five requests in ten seconds.",
                5,
                5,
                10
        ));
    }
}
