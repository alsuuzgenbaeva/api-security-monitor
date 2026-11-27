package com.apisecurity.monitor.anomaly.endpointscanning.service;

import com.apisecurity.monitor.anomaly.endpointscanning.config.EndpointScanningDetectionProperties;
import com.apisecurity.monitor.requestlog.event.RequestLoggedEvent;
import com.apisecurity.monitor.requestlog.repository.ApiRequestLogRepository;
import com.apisecurity.monitor.requestlog.repository.EndpointScanningWindowStatistics;
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
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class EndpointScanningDetectorTest {

    private static final Instant REQUEST_TIME = Instant.parse("2026-11-27T10:00:00Z");

    @Mock
    private ApiRequestLogRepository requestLogRepository;

    @Mock
    private SecurityEventService securityEventService;

    @Mock
    private EndpointScanningWindowStatistics statistics;

    private EndpointScanningDetectionProperties properties;
    private EndpointScanningDetector detector;

    @BeforeEach
    void setUp() {
        properties = new EndpointScanningDetectionProperties();
        detector = new EndpointScanningDetector(requestLogRepository, securityEventService, properties);
    }

    @Test
    void normalTrafficAndRepeatedErrorsOnOnePathDoNotTriggerOrWasteQueries() {
        detector.detect(event(200));
        verify(requestLogRepository, never()).summarizeEndpointScanningWindow(any(), any(), any());

        when(requestLogRepository.summarizeEndpointScanningWindow(
                "127.0.0.1", REQUEST_TIME.minusSeconds(60), REQUEST_TIME)).thenReturn(statistics);
        when(statistics.getUnsuccessfulRequestCount()).thenReturn(20L);
        when(statistics.getDistinctPathCount()).thenReturn(1L);

        detector.detect(event(404));

        verify(securityEventService, never()).createIfNotSuppressed(any(), any());
    }

    @Test
    void requiresBothThresholdsAndCreatesAccurateStructuredEvidenceAtTheBoundary() {
        when(requestLogRepository.summarizeEndpointScanningWindow(any(), any(), any())).thenReturn(statistics);
        when(statistics.getUnsuccessfulRequestCount()).thenReturn(7L, 8L, 8L);
        when(statistics.getDistinctPathCount()).thenReturn(5L, 4L, 5L);

        detector.detect(event(404));
        detector.detect(event(404));
        detector.detect(event(404));

        ArgumentCaptor<SecurityEventData> captor = ArgumentCaptor.forClass(SecurityEventData.class);
        verify(securityEventService).createIfNotSuppressed(captor.capture(), any(Duration.class));
        SecurityEventData data = captor.getValue();
        assertThat(data.eventType()).isEqualTo(SecurityEventType.ENDPOINT_SCANNING);
        assertThat(data.riskLevel()).isEqualTo(RiskLevel.MEDIUM);
        assertThat(data.sourceRequestLogId()).isEqualTo(91L);
        assertThat(data.observedRequestCount()).isEqualTo(8L);
        assertThat(data.configuredThreshold()).isEqualTo(8);
        assertThat(data.observedDistinctPathCount()).isEqualTo(5L);
        assertThat(data.configuredDistinctPathThreshold()).isEqualTo(5);
        assertThat(data.observedClientErrorCount()).isNull();
        assertThat(data.detectionReason())
                .contains("Potential endpoint-scanning indicator", "8 HTTP 404 requests", "5 distinct stored paths")
                .doesNotContain("/admin", "requestPath");
        verify(securityEventService).createIfNotSuppressed(data, Duration.ofSeconds(60));
    }

    @Test
    void usesInclusivePersistedRequestWindowAndCanBeDisabled() {
        when(requestLogRepository.summarizeEndpointScanningWindow(
                "127.0.0.1", REQUEST_TIME.minusSeconds(60), REQUEST_TIME)).thenReturn(statistics);

        detector.detect(event(404));

        verify(requestLogRepository).summarizeEndpointScanningWindow(
                "127.0.0.1", REQUEST_TIME.minusSeconds(60), REQUEST_TIME);

        properties.setEnabled(false);
        detector.detect(event(404));
        verify(requestLogRepository).summarizeEndpointScanningWindow(any(), any(), any());
    }

    @Test
    void listenerIsAfterCommitAndDetectionFailuresAreFailOpen() throws NoSuchMethodException {
        when(requestLogRepository.summarizeEndpointScanningWindow(any(), any(), any()))
                .thenThrow(new IllegalStateException("database unavailable"));

        assertThatCode(() -> detector.onRequestLogged(event(404))).doesNotThrowAnyException();

        TransactionalEventListener annotation = EndpointScanningDetector.class
                .getMethod("onRequestLogged", RequestLoggedEvent.class)
                .getAnnotation(TransactionalEventListener.class);
        assertThat(annotation).isNotNull();
        assertThat(annotation.phase()).isEqualTo(TransactionPhase.AFTER_COMMIT);
        assertThat(annotation.fallbackExecution()).isFalse();
    }

    @Test
    void concurrentObservationsUseNoSharedMutableDetectorState() throws Exception {
        when(requestLogRepository.summarizeEndpointScanningWindow(any(), any(), any())).thenReturn(statistics);
        when(statistics.getUnsuccessfulRequestCount()).thenReturn(8L);
        when(statistics.getDistinctPathCount()).thenReturn(5L);
        int taskCount = 12;
        ExecutorService executor = Executors.newFixedThreadPool(4);
        CountDownLatch start = new CountDownLatch(1);
        try {
            List<Future<Object>> futures = java.util.stream.IntStream.range(0, taskCount)
                    .mapToObj(index -> executor.submit(() -> {
                        start.await();
                        detector.onRequestLogged(new RequestLoggedEvent(
                                (long) index, REQUEST_TIME, "192.0.2." + index, 404, List.of()));
                        return null;
                    }))
                    .toList();
            start.countDown();
            for (Future<Object> future : futures) {
                future.get();
            }
        } finally {
            executor.shutdownNow();
        }

        verify(securityEventService, times(taskCount)).createIfNotSuppressed(any(), any());
    }

    private RequestLoggedEvent event(int responseStatus) {
        return new RequestLoggedEvent(91L, REQUEST_TIME, "127.0.0.1", responseStatus, List.of());
    }
}
