package com.apisecurity.monitor.securityevent.model;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Index;
import jakarta.persistence.Table;
import jakarta.persistence.UniqueConstraint;

import java.time.Instant;

@Entity
@Table(
        name = "security_event",
        indexes = {
                @Index(name = "idx_security_event_occurred_at", columnList = "occurred_at"),
                @Index(name = "idx_security_event_type_occurred_at", columnList = "event_type, occurred_at"),
                @Index(name = "idx_security_event_client_ip_occurred_at", columnList = "client_ip, occurred_at")
        },
        uniqueConstraints = @UniqueConstraint(
                name = "uk_security_event_deduplication_key",
                columnNames = "deduplication_key"
        )
)
public class SecurityEvent {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Enumerated(EnumType.STRING)
    @Column(name = "event_type", nullable = false, length = 64)
    private SecurityEventType eventType;

    @Enumerated(EnumType.STRING)
    @Column(name = "risk_level", nullable = false, length = 16)
    private RiskLevel riskLevel;

    @Column(name = "occurred_at", nullable = false)
    private Instant occurredAt;

    @Column(name = "client_ip", nullable = false, length = 45)
    private String clientIp;

    @Column(name = "detection_reason", nullable = false, length = 1000)
    private String detectionReason;

    @Column(name = "source_request_log_id", nullable = false)
    private Long sourceRequestLogId;

    @Column(name = "observed_request_count", nullable = false)
    private long observedRequestCount;

    @Column(name = "configured_threshold", nullable = false)
    private int configuredThreshold;

    @Column(name = "window_seconds", nullable = false)
    private long windowSeconds;

    @Column(name = "deduplication_key", nullable = false, length = 160)
    private String deduplicationKey;

    protected SecurityEvent() {
    }

    public SecurityEvent(SecurityEventData data, String deduplicationKey) {
        this.eventType = data.eventType();
        this.riskLevel = data.riskLevel();
        this.occurredAt = data.occurredAt();
        this.clientIp = data.clientIp();
        this.detectionReason = data.detectionReason();
        this.sourceRequestLogId = data.sourceRequestLogId();
        this.observedRequestCount = data.observedRequestCount();
        this.configuredThreshold = data.configuredThreshold();
        this.windowSeconds = data.windowSeconds();
        this.deduplicationKey = deduplicationKey;
    }

    public Long getId() {
        return id;
    }

    public SecurityEventType getEventType() {
        return eventType;
    }

    public RiskLevel getRiskLevel() {
        return riskLevel;
    }

    public Instant getOccurredAt() {
        return occurredAt;
    }

    public String getClientIp() {
        return clientIp;
    }

    public String getDetectionReason() {
        return detectionReason;
    }

    public Long getSourceRequestLogId() {
        return sourceRequestLogId;
    }

    public long getObservedRequestCount() {
        return observedRequestCount;
    }

    public int getConfiguredThreshold() {
        return configuredThreshold;
    }

    public long getWindowSeconds() {
        return windowSeconds;
    }

    public String getDeduplicationKey() {
        return deduplicationKey;
    }
}
