package com.apisecurity.monitor.requestlog.model;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Index;
import jakarta.persistence.Table;

import java.time.Instant;

@Entity
@Table(
        name = "api_request_log",
        indexes = {
                @Index(name = "idx_api_request_log_requested_at", columnList = "requested_at"),
                @Index(name = "idx_api_request_log_client_ip_requested_at", columnList = "client_ip, requested_at")
        }
)
public class ApiRequestLog {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "requested_at", nullable = false)
    private Instant requestedAt;

    @Column(name = "client_ip", nullable = false, length = 45)
    private String clientIp;

    @Column(name = "http_method", nullable = false, length = 16)
    private String httpMethod;

    @Column(name = "request_path", nullable = false, length = 2048)
    private String requestPath;

    @Column(name = "response_status", nullable = false)
    private int responseStatus;

    @Column(name = "duration_ms", nullable = false)
    private long durationMs;

    protected ApiRequestLog() {
    }

    public ApiRequestLog(RequestLogData data) {
        this.requestedAt = data.requestedAt();
        this.clientIp = data.clientIp();
        this.httpMethod = data.httpMethod();
        this.requestPath = data.requestPath();
        this.responseStatus = data.responseStatus();
        this.durationMs = data.durationMs();
    }

    public Long getId() {
        return id;
    }

    public Instant getRequestedAt() {
        return requestedAt;
    }

    public String getClientIp() {
        return clientIp;
    }

    public String getHttpMethod() {
        return httpMethod;
    }

    public String getRequestPath() {
        return requestPath;
    }

    public int getResponseStatus() {
        return responseStatus;
    }

    public long getDurationMs() {
        return durationMs;
    }
}
