package com.apisecurity.monitor.anomaly.errorrate.service;

import com.apisecurity.monitor.anomaly.errorrate.config.AbnormalErrorRateDetectionProperties;
import com.apisecurity.monitor.requestlog.event.RequestLoggedEvent;
import com.apisecurity.monitor.requestlog.repository.ApiRequestLogRepository;
import com.apisecurity.monitor.requestlog.repository.ErrorRateWindowStatistics;
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
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class AbnormalErrorRateDetectorTest {

    private static final Instant REQUEST_TIME = Instant.parse("2026-11-27T10:00:00Z");

    @Mock
    private ApiRequestLogRepository requestLogRepository;

    @Mock
    private SecurityEventService securityEventService;

    @Mock
    private ErrorRateWindowStatistics statistics;

    private AbnormalErrorRateDetectionProperties properties;
    private AbnormalErrorRateDetector detector;

    @BeforeEach
    void setUp() {
        properties = new AbnormalErrorRateDetectionProperties();
        detector = new AbnormalErrorRateDetector(requestLogRepository, securityEventService, properties);
    }

    @Test
    void successfulExcludedAndServerErrorStatusesDoNotRunAnAggregateQuery() {
        for (int status : List.of(200, 302, 401, 403, 429, 500, 503)) {
            detector.detect(event(status));
        }

        verify(requestLogRepository, never()).summarizeErrorRateWindow(any(), any(), any());
        verify(securityEventService, never()).createIfNotSuppressed(any(), any());
    }

    @Test
    void minimumSampleAndExactRateThresholdMustBothBeMet() {
        when(requestLogRepository.summarizeErrorRateWindow(any(), any(), any())).thenReturn(statistics);
        when(statistics.getTotalRequestCount()).thenReturn(9L, 10L, 10L);
        when(statistics.getClientErrorCount()).thenReturn(9L, 5L, 6L);
        when(statistics.getServerErrorCount()).thenReturn(0L);

        detector.detect(event(400));
        detector.detect(event(404));
        detector.detect(event(422));

        ArgumentCaptor<SecurityEventData> captor = ArgumentCaptor.forClass(SecurityEventData.class);
        verify(securityEventService).createIfNotSuppressed(captor.capture(), any(Duration.class));
        SecurityEventData data = captor.getValue();
        assertThat(data.eventType()).isEqualTo(SecurityEventType.ABNORMAL_ERROR_RATE);
        assertThat(data.riskLevel()).isEqualTo(RiskLevel.MEDIUM);
        assertThat(data.sourceRequestLogId()).isEqualTo(92L);
        assertThat(data.observedRequestCount()).isEqualTo(10L);
        assertThat(data.configuredThreshold()).isEqualTo(10);
        assertThat(data.observedClientErrorCount()).isEqualTo(6L);
        assertThat(data.configuredClientErrorRatePercent()).isEqualTo(60);
        assertThat(data.observedDistinctPathCount()).isNull();
        verify(securityEventService).createIfNotSuppressed(data, Duration.ofSeconds(60));
    }

    @Test
    void serverErrorsAreEvidenceOnlyAndNeverPartOfTheSuspiciousNumerator() {
        when(requestLogRepository.summarizeErrorRateWindow(
                "127.0.0.1", REQUEST_TIME.minusSeconds(60), REQUEST_TIME)).thenReturn(statistics);
        when(statistics.getTotalRequestCount()).thenReturn(10L);
        when(statistics.getClientErrorCount()).thenReturn(6L);
        when(statistics.getServerErrorCount()).thenReturn(3L);

        detector.detect(event(404));

        ArgumentCaptor<SecurityEventData> captor = ArgumentCaptor.forClass(SecurityEventData.class);
        verify(securityEventService).createIfNotSuppressed(captor.capture(), any());
        assertThat(captor.getValue().detectionReason())
                .contains("6 eligible client errors", "10 logged requests", "3 server errors")
                .doesNotContain("404", "/missing");
    }

    @Test
    void exactComparisonIsOverflowSafeAndDoesNotRoundPrematurely() {
        assertThat(AbnormalErrorRateDetector.meetsRateThreshold(6, 10, 60)).isTrue();
        assertThat(AbnormalErrorRateDetector.meetsRateThreshold(599, 1_000, 60)).isFalse();
        assertThat(AbnormalErrorRateDetector.meetsRateThreshold(600, 1_000, 60)).isTrue();
        assertThat(AbnormalErrorRateDetector.meetsRateThreshold(
                Long.MAX_VALUE, Long.MAX_VALUE, 100)).isTrue();
        assertThat(AbnormalErrorRateDetector.meetsRateThreshold(
                Long.MAX_VALUE - 1, Long.MAX_VALUE, 100)).isFalse();
    }

    @Test
    void usesInclusivePersistedRequestWindowAndCanBeDisabled() {
        when(requestLogRepository.summarizeErrorRateWindow(
                "127.0.0.1", REQUEST_TIME.minusSeconds(60), REQUEST_TIME)).thenReturn(statistics);

        detector.detect(event(400));

        verify(requestLogRepository).summarizeErrorRateWindow(
                "127.0.0.1", REQUEST_TIME.minusSeconds(60), REQUEST_TIME);

        properties.setEnabled(false);
        detector.detect(event(400));
        verify(requestLogRepository).summarizeErrorRateWindow(any(), any(), any());
    }

    @Test
    void listenerIsAfterCommitAndDetectionFailuresAreFailOpen() throws NoSuchMethodException {
        when(requestLogRepository.summarizeErrorRateWindow(any(), any(), any()))
                .thenThrow(new IllegalStateException("database unavailable"));

        assertThatCode(() -> detector.onRequestLogged(event(400))).doesNotThrowAnyException();

        TransactionalEventListener annotation = AbnormalErrorRateDetector.class
                .getMethod("onRequestLogged", RequestLoggedEvent.class)
                .getAnnotation(TransactionalEventListener.class);
        assertThat(annotation).isNotNull();
        assertThat(annotation.phase()).isEqualTo(TransactionPhase.AFTER_COMMIT);
        assertThat(annotation.fallbackExecution()).isFalse();
    }

    private RequestLoggedEvent event(int responseStatus) {
        return new RequestLoggedEvent(92L, REQUEST_TIME, "127.0.0.1", responseStatus, List.of());
    }
}
