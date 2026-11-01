package com.apisecurity.monitor.requestlog.service;

import com.apisecurity.monitor.requestlog.model.ApiRequestLog;
import com.apisecurity.monitor.requestlog.model.RequestLogData;
import com.apisecurity.monitor.requestlog.repository.ApiRequestLogRepository;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.verify;

@ExtendWith(MockitoExtension.class)
class ApiRequestLogServiceTest {

    @Mock
    private ApiRequestLogRepository repository;

    @Test
    void savesRequestMetadataAndNormalizesNegativeDuration() {
        ApiRequestLogService service = new ApiRequestLogService(repository);
        Instant timestamp = Instant.parse("2026-11-02T10:15:30Z");

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
    }
}
