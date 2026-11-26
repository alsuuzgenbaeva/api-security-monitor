package com.apisecurity.monitor.anomaly.payload.service;

import com.apisecurity.monitor.anomaly.payload.config.QueryPayloadDetectionProperties;
import com.apisecurity.monitor.anomaly.payload.model.PayloadDetectionFinding;
import com.apisecurity.monitor.anomaly.payload.model.PayloadDetectionFinding.InputLocation;
import com.apisecurity.monitor.anomaly.payload.model.PayloadDetectionFinding.SignatureIdentifier;
import com.apisecurity.monitor.requestlog.event.RequestLoggedEvent;
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
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

@ExtendWith(MockitoExtension.class)
class QueryPayloadAttackDetectorTest {

    private static final Instant REQUEST_TIME = Instant.parse("2026-11-26T12:00:00Z");

    @Mock
    private SecurityEventService securityEventService;

    private QueryPayloadDetectionProperties properties;
    private QueryPayloadAttackDetector detector;

    @BeforeEach
    void setUp() {
        properties = new QueryPayloadDetectionProperties();
        detector = new QueryPayloadAttackDetector(securityEventService, properties);
    }

    @Test
    void groupsSameTypeFindingsIntoOnePrivacySafeEvent() {
        detector.detect(event(List.of(
                finding(SignatureIdentifier.XSS_SCRIPT_TAG),
                finding(SignatureIdentifier.XSS_EVENT_HANDLER))));

        ArgumentCaptor<SecurityEventData> captor = ArgumentCaptor.forClass(SecurityEventData.class);
        verify(securityEventService).createIfNotSuppressed(captor.capture(), eq(Duration.ofSeconds(30)));
        SecurityEventData data = captor.getValue();
        assertThat(data.eventType()).isEqualTo(SecurityEventType.XSS_ATTEMPT);
        assertThat(data.riskLevel()).isEqualTo(RiskLevel.HIGH);
        assertThat(data.occurredAt()).isEqualTo(REQUEST_TIME);
        assertThat(data.clientIp()).isEqualTo("127.0.0.1");
        assertThat(data.sourceRequestLogId()).isEqualTo(77L);
        assertThat(data.observedRequestCount()).isEqualTo(2);
        assertThat(data.configuredThreshold()).isEqualTo(1);
        assertThat(data.windowSeconds()).isZero();
        assertThat(data.detectionReason())
                .contains("Potential XSS attempt indicator", "QUERY_PARAMETER",
                        "XSS_EVENT_HANDLER", "XSS_SCRIPT_TAG")
                .doesNotContain("<script>", "alert", "token", "password");
    }

    @Test
    void createsIndependentEventsForXssAndSqlInjectionFindings() {
        detector.detect(event(List.of(
                finding(SignatureIdentifier.XSS_SCRIPT_TAG),
                finding(SignatureIdentifier.SQLI_UNION_SELECT))));

        ArgumentCaptor<SecurityEventData> captor = ArgumentCaptor.forClass(SecurityEventData.class);
        verify(securityEventService, times(2))
                .createIfNotSuppressed(captor.capture(), eq(Duration.ofSeconds(30)));
        assertThat(captor.getAllValues()).extracting(SecurityEventData::eventType)
                .containsExactlyInAnyOrder(
                        SecurityEventType.XSS_ATTEMPT,
                        SecurityEventType.SQL_INJECTION_ATTEMPT);
    }

    @Test
    void disabledDetectionDoesNotCreateEvents() {
        properties.setEnabled(false);
        detector.detect(event(List.of(finding(SignatureIdentifier.XSS_SCRIPT_TAG))));

        verify(securityEventService, never()).createIfNotSuppressed(any(), any());
    }

    @Test
    void emptyFindingsDoNotCreateEventsWhileDetectionIsEnabled() {
        detector.detect(event(List.of()));

        assertThat(properties.isEnabled()).isTrue();
        verify(securityEventService, never()).createIfNotSuppressed(any(), any());
    }

    @Test
    void failureForOneEventTypeDoesNotPreventTheOtherType() {
        doAnswer(invocation -> {
            SecurityEventData data = invocation.getArgument(0);
            if (data.eventType() == SecurityEventType.XSS_ATTEMPT) {
                throw new IllegalStateException("XSS event persistence failed");
            }
            return true;
        }).when(securityEventService).createIfNotSuppressed(any(), any());

        assertThatCode(() -> detector.onRequestLogged(event(List.of(
                finding(SignatureIdentifier.XSS_SCRIPT_TAG),
                finding(SignatureIdentifier.SQLI_UNION_SELECT)))))
                .doesNotThrowAnyException();

        ArgumentCaptor<SecurityEventData> captor = ArgumentCaptor.forClass(SecurityEventData.class);
        verify(securityEventService, times(2)).createIfNotSuppressed(captor.capture(), any());
        assertThat(captor.getAllValues()).extracting(SecurityEventData::eventType)
                .containsExactly(
                        SecurityEventType.XSS_ATTEMPT,
                        SecurityEventType.SQL_INJECTION_ATTEMPT);
    }

    @Test
    void eventCreationFailureDoesNotEscapeListener() {
        doThrow(new IllegalStateException("database unavailable"))
                .when(securityEventService).createIfNotSuppressed(any(), any());

        assertThatCode(() -> detector.onRequestLogged(
                event(List.of(finding(SignatureIdentifier.SQLI_UNION_SELECT)))))
                .doesNotThrowAnyException();
    }

    @Test
    void listenerRunsAfterRequestLogCommit() throws NoSuchMethodException {
        TransactionalEventListener annotation = QueryPayloadAttackDetector.class
                .getMethod("onRequestLogged", RequestLoggedEvent.class)
                .getAnnotation(TransactionalEventListener.class);

        assertThat(annotation).isNotNull();
        assertThat(annotation.phase()).isEqualTo(TransactionPhase.AFTER_COMMIT);
        assertThat(annotation.fallbackExecution()).isFalse();
    }

    private RequestLoggedEvent event(List<PayloadDetectionFinding> findings) {
        return new RequestLoggedEvent(77L, REQUEST_TIME, "127.0.0.1", findings);
    }

    private PayloadDetectionFinding finding(SignatureIdentifier identifier) {
        return new PayloadDetectionFinding(
                identifier.eventType(), InputLocation.QUERY_PARAMETER, identifier);
    }
}
