package com.apisecurity.monitor.securityevent.service;

import com.apisecurity.monitor.securityevent.model.RiskLevel;
import com.apisecurity.monitor.securityevent.model.SecurityEventData;
import com.apisecurity.monitor.securityevent.model.SecurityEventType;
import com.apisecurity.monitor.securityevent.repository.SecurityEventRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.transaction.annotation.Transactional;

import java.time.Duration;
import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class SecurityEventServiceTest {

    private static final Instant OCCURRED_AT = Instant.parse("2026-11-02T10:15:30Z");

    @Mock
    private SecurityEventRepository repository;

    @Mock
    private SecurityEventWriter writer;

    private SecurityEventService service;

    @BeforeEach
    void setUp() {
        service = new SecurityEventService(repository, writer);
    }

    @Test
    void cooldownSuppressesRecentMatchingEvent() {
        when(repository.existsByEventTypeAndClientIpAndOccurredAtGreaterThanEqual(
                SecurityEventType.EXCESSIVE_REQUESTS, "127.0.0.1", OCCURRED_AT.minusSeconds(30)))
                .thenReturn(true);

        boolean created = service.createIfNotSuppressed(data(), Duration.ofSeconds(30));

        assertThat(created).isFalse();
        verify(writer, never()).insert(any(), any());
    }

    @Test
    void persistsEventWithDeterministicTimeBucketKey() {
        boolean created = service.createIfNotSuppressed(data(), Duration.ofSeconds(30));

        assertThat(created).isTrue();
        long expectedBucket = Math.floorDiv(OCCURRED_AT.getEpochSecond(), 30);
        verify(writer).insert(data(), "EXCESSIVE_REQUESTS|127.0.0.1|" + expectedBucket);
    }

    @Test
    void differentEventTypesUseIndependentSuppressionKeys() {
        SecurityEventData xss = data(SecurityEventType.XSS_ATTEMPT);
        SecurityEventData sqlInjection = data(SecurityEventType.SQL_INJECTION_ATTEMPT);
        SecurityEventData bruteForce = data(SecurityEventType.BRUTE_FORCE_ATTEMPT);
        SecurityEventData endpointScanning = data(SecurityEventType.ENDPOINT_SCANNING);
        SecurityEventData abnormalErrorRate = data(SecurityEventType.ABNORMAL_ERROR_RATE);

        assertThat(service.createIfNotSuppressed(xss, Duration.ofSeconds(30))).isTrue();
        assertThat(service.createIfNotSuppressed(sqlInjection, Duration.ofSeconds(30))).isTrue();
        assertThat(service.createIfNotSuppressed(bruteForce, Duration.ofSeconds(30))).isTrue();
        assertThat(service.createIfNotSuppressed(endpointScanning, Duration.ofSeconds(30))).isTrue();
        assertThat(service.createIfNotSuppressed(abnormalErrorRate, Duration.ofSeconds(30))).isTrue();

        long expectedBucket = Math.floorDiv(OCCURRED_AT.getEpochSecond(), 30);
        verify(writer).insert(xss, "XSS_ATTEMPT|127.0.0.1|" + expectedBucket);
        verify(writer).insert(sqlInjection, "SQL_INJECTION_ATTEMPT|127.0.0.1|" + expectedBucket);
        verify(writer).insert(bruteForce, "BRUTE_FORCE_ATTEMPT|127.0.0.1|" + expectedBucket);
        verify(writer).insert(endpointScanning, "ENDPOINT_SCANNING|127.0.0.1|" + expectedBucket);
        verify(writer).insert(abnormalErrorRate, "ABNORMAL_ERROR_RATE|127.0.0.1|" + expectedBucket);
    }

    @Test
    void concurrentDuplicateKeyIsTreatedAsSuppression() {
        long expectedBucket = Math.floorDiv(OCCURRED_AT.getEpochSecond(), 30);
        String key = "EXCESSIVE_REQUESTS|127.0.0.1|" + expectedBucket;
        doThrow(new DataIntegrityViolationException("duplicate key"))
                .when(writer).insert(eq(data()), any());
        when(repository.existsByDeduplicationKey(key)).thenReturn(true);

        boolean created = service.createIfNotSuppressed(data(), Duration.ofSeconds(30));

        assertThat(created).isFalse();
    }

    @Test
    void unrelatedIntegrityFailureIsNotMisclassifiedAsDuplicate() {
        DataIntegrityViolationException failure = new DataIntegrityViolationException("other constraint");
        doThrow(failure).when(writer).insert(eq(data()), any());

        assertThatThrownBy(() -> service.createIfNotSuppressed(data(), Duration.ofSeconds(30)))
                .isSameAs(failure);
    }

    @Test
    void cooldownLookupUsesReadOnlyTransaction() throws NoSuchMethodException {
        Transactional transactional = SecurityEventService.class
                .getMethod("createIfNotSuppressed", SecurityEventData.class, Duration.class)
                .getAnnotation(Transactional.class);

        assertThat(transactional).isNotNull();
        assertThat(transactional.readOnly()).isTrue();
    }

    private SecurityEventData data() {
        return data(SecurityEventType.EXCESSIVE_REQUESTS);
    }

    private SecurityEventData data(SecurityEventType eventType) {
        return new SecurityEventData(
                eventType,
                RiskLevel.MEDIUM,
                OCCURRED_AT,
                "127.0.0.1",
                "Observed 5 requests from one client IP within 10 seconds; configured threshold is 5.",
                99L,
                5,
                5,
                10
        );
    }
}
