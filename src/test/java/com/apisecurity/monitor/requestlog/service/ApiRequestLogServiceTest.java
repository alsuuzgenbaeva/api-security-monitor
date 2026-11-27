package com.apisecurity.monitor.requestlog.service;

import com.apisecurity.monitor.anomaly.payload.model.PayloadDetectionFinding;
import com.apisecurity.monitor.anomaly.payload.model.PayloadDetectionFinding.InputLocation;
import com.apisecurity.monitor.anomaly.payload.model.PayloadDetectionFinding.SignatureIdentifier;
import com.apisecurity.monitor.requestlog.event.RequestLoggedEvent;
import com.apisecurity.monitor.requestlog.model.ApiRequestLog;
import com.apisecurity.monitor.requestlog.model.RequestLogData;
import com.apisecurity.monitor.requestlog.repository.ApiRequestLogRepository;
import com.apisecurity.monitor.securityevent.model.SecurityEventType;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.test.util.ReflectionTestUtils;

import java.time.Instant;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class ApiRequestLogServiceTest {

    @Mock
    private ApiRequestLogRepository repository;

    @Mock
    private ApplicationEventPublisher eventPublisher;

    @Test
    void savesRequestMetadataAndPublishesEvent() {
        ApiRequestLogService service = new ApiRequestLogService(repository, eventPublisher);
        Instant timestamp = Instant.parse("2026-11-02T10:15:30Z");
        when(repository.saveAndFlush(any(ApiRequestLog.class))).thenAnswer(invocation -> {
            ApiRequestLog log = invocation.getArgument(0);
            ReflectionTestUtils.setField(log, "id", 42L);
            return log;
        });

        service.save(new RequestLogData(timestamp, "127.0.0.1", "GET", "/api/test", 200, -1));

        ArgumentCaptor<ApiRequestLog> captor = ArgumentCaptor.forClass(ApiRequestLog.class);
        verify(repository).saveAndFlush(captor.capture());
        ApiRequestLog saved = captor.getValue();

        assertThat(saved.getRequestedAt()).isEqualTo(timestamp);
        assertThat(saved.getClientIp()).isEqualTo("127.0.0.1");
        assertThat(saved.getHttpMethod()).isEqualTo("GET");
        assertThat(saved.getRequestPath()).isEqualTo("/api/test");
        assertThat(saved.getResponseStatus()).isEqualTo(200);
        assertThat(saved.getDurationMs()).isZero();

        ArgumentCaptor<RequestLoggedEvent> eventCaptor = ArgumentCaptor.forClass(RequestLoggedEvent.class);
        verify(eventPublisher).publishEvent(eventCaptor.capture());
        assertThat(eventCaptor.getValue().requestLogId()).isEqualTo(42L);
        assertThat(eventCaptor.getValue().requestedAt()).isEqualTo(timestamp);
        assertThat(eventCaptor.getValue().clientIp()).isEqualTo("127.0.0.1");
        assertThat(eventCaptor.getValue().responseStatus()).isEqualTo(200);
        assertThat(eventCaptor.getValue().payloadFindings()).isEmpty();
    }

    @Test
    void publishesOnlyPrivacySafeFindingsAfterLogPersistence() {
        ApiRequestLogService service = new ApiRequestLogService(repository, eventPublisher);
        Instant timestamp = Instant.parse("2026-11-02T10:15:30Z");
        PayloadDetectionFinding finding = new PayloadDetectionFinding(
                SecurityEventType.SQL_INJECTION_ATTEMPT,
                InputLocation.QUERY_PARAMETER,
                SignatureIdentifier.SQLI_UNION_SELECT);
        when(repository.saveAndFlush(any(ApiRequestLog.class))).thenAnswer(invocation -> {
            ApiRequestLog log = invocation.getArgument(0);
            ReflectionTestUtils.setField(log, "id", 43L);
            return log;
        });

        service.save(
                new RequestLogData(timestamp, "127.0.0.1", "GET", "/api/test", 200, 1),
                List.of(finding));

        ArgumentCaptor<RequestLoggedEvent> eventCaptor = ArgumentCaptor.forClass(RequestLoggedEvent.class);
        verify(eventPublisher).publishEvent(eventCaptor.capture());
        assertThat(eventCaptor.getValue().payloadFindings()).containsExactly(finding);
        assertThat(eventCaptor.getValue().payloadFindings().toString())
                .doesNotContain("UNION SELECT", "password", "token");
    }

    @Test
    void failedPersistenceDoesNotPublishDetectionEvent() {
        ApiRequestLogService service = new ApiRequestLogService(repository, eventPublisher);
        doThrow(new IllegalStateException("database unavailable"))
                .when(repository).saveAndFlush(any(ApiRequestLog.class));

        assertThatThrownBy(() -> service.save(new RequestLogData(
                Instant.parse("2026-11-02T10:15:30Z"), "127.0.0.1", "GET", "/api/test", 200, 1)))
                .isInstanceOf(IllegalStateException.class);

        verify(eventPublisher, never()).publishEvent(any());
    }

    @Test
    void saveUsesIndependentTransaction() throws NoSuchMethodException {
        Transactional transactional = ApiRequestLogService.class
                .getMethod("save", RequestLogData.class)
                .getAnnotation(Transactional.class);

        assertThat(transactional).isNotNull();
        assertThat(transactional.propagation()).isEqualTo(Propagation.REQUIRES_NEW);

        Transactional findingsTransactional = ApiRequestLogService.class
                .getMethod("save", RequestLogData.class, List.class)
                .getAnnotation(Transactional.class);
        assertThat(findingsTransactional).isNotNull();
        assertThat(findingsTransactional.propagation()).isEqualTo(Propagation.REQUIRES_NEW);
    }
}
