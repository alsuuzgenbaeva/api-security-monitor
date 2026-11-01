package com.apisecurity.monitor.anomaly.excessiverequests.service;

import com.apisecurity.monitor.anomaly.excessiverequests.config.ExcessiveRequestRuleProperties;
import com.apisecurity.monitor.requestlog.event.RequestLoggedEvent;
import com.apisecurity.monitor.requestlog.repository.ApiRequestLogRepository;
import com.apisecurity.monitor.securityevent.model.RiskLevel;
import com.apisecurity.monitor.securityevent.model.SecurityEventData;
import com.apisecurity.monitor.securityevent.model.SecurityEventType;
import com.apisecurity.monitor.securityevent.service.SecurityEventService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.transaction.event.TransactionPhase;
import org.springframework.transaction.event.TransactionalEventListener;

import java.time.Duration;
import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class ExcessiveRequestDetectorTest {

    private static final Instant REQUEST_TIME = Instant.parse("2026-11-02T10:15:30Z");

    @Mock
    private ApiRequestLogRepository requestLogRepository;

    @Mock
    private SecurityEventService securityEventService;

    private ExcessiveRequestRuleProperties properties;
    private ExcessiveRequestDetector detector;

    @BeforeEach
    void setUp() {
        properties = new ExcessiveRequestRuleProperties();
        detector = new ExcessiveRequestDetector(requestLogRepository, securityEventService, properties);
    }

    @Test
    void doesNotCreateEventBelowThreshold() {
        when(requestLogRepository.countByClientIpAndRequestedAtGreaterThanEqual(
                "127.0.0.1", REQUEST_TIME.minusSeconds(10))).thenReturn(4L);

        detector.detect(event());

        verify(securityEventService, never()).createIfNotSuppressed(any(), any());
    }

    @Test
    void createsMediumRiskEventExactlyAtThreshold() {
        when(requestLogRepository.countByClientIpAndRequestedAtGreaterThanEqual(
                "127.0.0.1", REQUEST_TIME.minusSeconds(10))).thenReturn(5L);

        detector.detect(event());

        ArgumentCaptor<SecurityEventData> captor = ArgumentCaptor.forClass(SecurityEventData.class);
        verify(securityEventService).createIfNotSuppressed(captor.capture(), any(Duration.class));
        SecurityEventData data = captor.getValue();
        assertThat(data.eventType()).isEqualTo(SecurityEventType.EXCESSIVE_REQUESTS);
        assertThat(data.riskLevel()).isEqualTo(RiskLevel.MEDIUM);
        assertThat(data.occurredAt()).isEqualTo(REQUEST_TIME);
        assertThat(data.clientIp()).isEqualTo("127.0.0.1");
        assertThat(data.sourceRequestLogId()).isEqualTo(99L);
        assertThat(data.observedRequestCount()).isEqualTo(5L);
        assertThat(data.configuredThreshold()).isEqualTo(5);
        assertThat(data.windowSeconds()).isEqualTo(10L);
        assertThat(data.detectionReason()).contains("5 requests", "10 seconds", "threshold is 5");
        verify(securityEventService).createIfNotSuppressed(data, Duration.ofSeconds(30));
    }

    @Test
    void disabledRuleDoesNotQueryDatabase() {
        properties.setEnabled(false);

        detector.detect(event());

        verify(requestLogRepository, never()).countByClientIpAndRequestedAtGreaterThanEqual(any(), any());
        verify(securityEventService, never()).createIfNotSuppressed(any(), any());
    }

    @Test
    void detectionFailureDoesNotEscapeListener() {
        when(requestLogRepository.countByClientIpAndRequestedAtGreaterThanEqual(any(), any()))
                .thenThrow(new IllegalStateException("database unavailable"));

        assertThatCode(() -> detector.onRequestLogged(event())).doesNotThrowAnyException();
    }

    @Test
    void listenerRunsAfterCommit() throws NoSuchMethodException {
        TransactionalEventListener annotation = ExcessiveRequestDetector.class
                .getMethod("onRequestLogged", RequestLoggedEvent.class)
                .getAnnotation(TransactionalEventListener.class);

        assertThat(annotation).isNotNull();
        assertThat(annotation.phase()).isEqualTo(TransactionPhase.AFTER_COMMIT);
        assertThat(annotation.fallbackExecution()).isFalse();
    }

    private RequestLoggedEvent event() {
        return new RequestLoggedEvent(99L, REQUEST_TIME, "127.0.0.1");
    }
}
