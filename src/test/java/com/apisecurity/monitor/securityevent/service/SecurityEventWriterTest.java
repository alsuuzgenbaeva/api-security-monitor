package com.apisecurity.monitor.securityevent.service;

import com.apisecurity.monitor.securityevent.model.RiskLevel;
import com.apisecurity.monitor.securityevent.model.SecurityEvent;
import com.apisecurity.monitor.securityevent.model.SecurityEventData;
import com.apisecurity.monitor.securityevent.model.SecurityEventType;
import com.apisecurity.monitor.securityevent.repository.SecurityEventRepository;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.verify;

@ExtendWith(MockitoExtension.class)
class SecurityEventWriterTest {

    @Mock
    private SecurityEventRepository repository;

    @Test
    void mapsAndFlushesSecurityEvent() {
        SecurityEventWriter writer = new SecurityEventWriter(repository);
        SecurityEventData data = new SecurityEventData(
                SecurityEventType.EXCESSIVE_REQUESTS,
                RiskLevel.MEDIUM,
                Instant.parse("2026-11-02T10:15:30Z"),
                "127.0.0.1",
                "Threshold reached",
                99L,
                5,
                5,
                10
        );

        writer.insert(data, "dedup-key");

        ArgumentCaptor<SecurityEvent> captor = ArgumentCaptor.forClass(SecurityEvent.class);
        verify(repository).saveAndFlush(captor.capture());
        SecurityEvent saved = captor.getValue();
        assertThat(saved.getEventType()).isEqualTo(SecurityEventType.EXCESSIVE_REQUESTS);
        assertThat(saved.getRiskLevel()).isEqualTo(RiskLevel.MEDIUM);
        assertThat(saved.getOccurredAt()).isEqualTo(data.occurredAt());
        assertThat(saved.getClientIp()).isEqualTo("127.0.0.1");
        assertThat(saved.getDetectionReason()).isEqualTo("Threshold reached");
        assertThat(saved.getSourceRequestLogId()).isEqualTo(99L);
        assertThat(saved.getObservedRequestCount()).isEqualTo(5L);
        assertThat(saved.getConfiguredThreshold()).isEqualTo(5);
        assertThat(saved.getWindowSeconds()).isEqualTo(10L);
        assertThat(saved.getDeduplicationKey()).isEqualTo("dedup-key");
    }

    @Test
    void mapsAuthenticationEventWithoutFabricatingARequestLogIdentifier() {
        SecurityEventWriter writer = new SecurityEventWriter(repository);
        SecurityEventData data = new SecurityEventData(
                SecurityEventType.BRUTE_FORCE_ATTEMPT,
                RiskLevel.HIGH,
                Instant.parse("2026-11-27T08:00:00Z"),
                "127.0.0.1",
                "Potential brute-force indicator.",
                null,
                5,
                5,
                60
        );

        writer.insert(data, "brute-force-dedup-key");

        ArgumentCaptor<SecurityEvent> captor = ArgumentCaptor.forClass(SecurityEvent.class);
        verify(repository).saveAndFlush(captor.capture());
        assertThat(captor.getValue().getEventType()).isEqualTo(SecurityEventType.BRUTE_FORCE_ATTEMPT);
        assertThat(captor.getValue().getSourceRequestLogId()).isNull();
    }

    @Test
    void insertUsesIndependentTransaction() throws NoSuchMethodException {
        Transactional transactional = SecurityEventWriter.class
                .getMethod("insert", SecurityEventData.class, String.class)
                .getAnnotation(Transactional.class);

        assertThat(transactional).isNotNull();
        assertThat(transactional.propagation()).isEqualTo(Propagation.REQUIRES_NEW);
    }
}
