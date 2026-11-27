package com.apisecurity.monitor.anomaly;

import com.apisecurity.monitor.anomaly.endpointscanning.config.EndpointScanningDetectionProperties;
import com.apisecurity.monitor.anomaly.endpointscanning.service.EndpointScanningDetector;
import com.apisecurity.monitor.anomaly.errorrate.config.AbnormalErrorRateDetectionProperties;
import com.apisecurity.monitor.anomaly.errorrate.service.AbnormalErrorRateDetector;
import com.apisecurity.monitor.requestlog.event.RequestLoggedEvent;
import com.apisecurity.monitor.requestlog.repository.ApiRequestLogRepository;
import com.apisecurity.monitor.requestlog.repository.EndpointScanningWindowStatistics;
import com.apisecurity.monitor.requestlog.repository.ErrorRateWindowStatistics;
import com.apisecurity.monitor.securityevent.model.SecurityEventData;
import com.apisecurity.monitor.securityevent.model.SecurityEventType;
import com.apisecurity.monitor.securityevent.service.SecurityEventService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Instant;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class BehavioralRequestDetectorsTest {

    @Mock
    private ApiRequestLogRepository requestLogRepository;

    @Mock
    private SecurityEventService securityEventService;

    @Mock
    private EndpointScanningWindowStatistics endpointStatistics;

    @Mock
    private ErrorRateWindowStatistics errorStatistics;

    private EndpointScanningDetector endpointDetector;
    private AbnormalErrorRateDetector errorRateDetector;

    @BeforeEach
    void setUp() {
        endpointDetector = new EndpointScanningDetector(
                requestLogRepository,
                securityEventService,
                new EndpointScanningDetectionProperties());
        errorRateDetector = new AbnormalErrorRateDetector(
                requestLogRepository,
                securityEventService,
                new AbnormalErrorRateDetectionProperties());
    }

    @Test
    void oneRequestCanCreateBothIndependentEventTypes() {
        when(requestLogRepository.summarizeEndpointScanningWindow(any(), any(), any()))
                .thenReturn(endpointStatistics);
        when(endpointStatistics.getUnsuccessfulRequestCount()).thenReturn(8L);
        when(endpointStatistics.getDistinctPathCount()).thenReturn(5L);
        when(requestLogRepository.summarizeErrorRateWindow(any(), any(), any())).thenReturn(errorStatistics);
        when(errorStatistics.getTotalRequestCount()).thenReturn(10L);
        when(errorStatistics.getClientErrorCount()).thenReturn(6L);

        RequestLoggedEvent request = request();
        endpointDetector.onRequestLogged(request);
        errorRateDetector.onRequestLogged(request);

        ArgumentCaptor<SecurityEventData> captor = ArgumentCaptor.forClass(SecurityEventData.class);
        verify(securityEventService, org.mockito.Mockito.times(2))
                .createIfNotSuppressed(captor.capture(), any());
        assertThat(captor.getAllValues()).extracting(SecurityEventData::eventType)
                .containsExactlyInAnyOrder(
                        SecurityEventType.ENDPOINT_SCANNING,
                        SecurityEventType.ABNORMAL_ERROR_RATE);
    }

    @Test
    void oneDetectorPersistenceFailureDoesNotPreventTheOtherDetectorAttempt() {
        when(requestLogRepository.summarizeEndpointScanningWindow(any(), any(), any()))
                .thenReturn(endpointStatistics);
        when(endpointStatistics.getUnsuccessfulRequestCount()).thenReturn(8L);
        when(endpointStatistics.getDistinctPathCount()).thenReturn(5L);
        when(requestLogRepository.summarizeErrorRateWindow(any(), any(), any())).thenReturn(errorStatistics);
        when(errorStatistics.getTotalRequestCount()).thenReturn(10L);
        when(errorStatistics.getClientErrorCount()).thenReturn(6L);
        when(securityEventService.createIfNotSuppressed(
                argThat(data -> data.eventType() == SecurityEventType.ENDPOINT_SCANNING), any()))
                .thenThrow(new IllegalStateException("endpoint event persistence unavailable"));

        RequestLoggedEvent request = request();
        endpointDetector.onRequestLogged(request);
        errorRateDetector.onRequestLogged(request);

        verify(securityEventService).createIfNotSuppressed(
                argThat(data -> data.eventType() == SecurityEventType.ENDPOINT_SCANNING), any());
        verify(securityEventService).createIfNotSuppressed(
                argThat(data -> data.eventType() == SecurityEventType.ABNORMAL_ERROR_RATE), any());
    }

    private RequestLoggedEvent request() {
        return new RequestLoggedEvent(
                93L,
                Instant.parse("2026-11-27T10:00:00Z"),
                "127.0.0.1",
                404,
                List.of());
    }
}
