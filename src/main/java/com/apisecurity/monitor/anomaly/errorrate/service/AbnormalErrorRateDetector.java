package com.apisecurity.monitor.anomaly.errorrate.service;

import com.apisecurity.monitor.anomaly.errorrate.config.AbnormalErrorRateDetectionProperties;
import com.apisecurity.monitor.requestlog.event.RequestLoggedEvent;
import com.apisecurity.monitor.requestlog.repository.ApiRequestLogRepository;
import com.apisecurity.monitor.requestlog.repository.ErrorRateWindowStatistics;
import com.apisecurity.monitor.securityevent.model.RiskLevel;
import com.apisecurity.monitor.securityevent.model.SecurityEventData;
import com.apisecurity.monitor.securityevent.model.SecurityEventType;
import com.apisecurity.monitor.securityevent.service.SecurityEventService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.event.TransactionPhase;
import org.springframework.transaction.event.TransactionalEventListener;

import java.math.BigInteger;
import java.time.Instant;

@Service
public class AbnormalErrorRateDetector {

    private static final Logger logger = LoggerFactory.getLogger(AbnormalErrorRateDetector.class);

    private final ApiRequestLogRepository requestLogRepository;
    private final SecurityEventService securityEventService;
    private final AbnormalErrorRateDetectionProperties properties;

    public AbnormalErrorRateDetector(
            ApiRequestLogRepository requestLogRepository,
            SecurityEventService securityEventService,
            AbnormalErrorRateDetectionProperties properties
    ) {
        this.requestLogRepository = requestLogRepository;
        this.securityEventService = securityEventService;
        this.properties = properties;
    }

    @TransactionalEventListener(phase = TransactionPhase.AFTER_COMMIT)
    public void onRequestLogged(RequestLoggedEvent event) {
        try {
            detect(event);
        } catch (RuntimeException detectionFailure) {
            logger.error("Abnormal-error-rate detection failed; the original response is unchanged");
        }
    }

    void detect(RequestLoggedEvent event) {
        if (!properties.isEnabled() || !isEligibleClientError(event.responseStatus())) {
            return;
        }

        Instant windowStart = event.requestedAt().minus(properties.getWindow());
        ErrorRateWindowStatistics statistics = requestLogRepository
                .summarizeErrorRateWindow(event.clientIp(), windowStart, event.requestedAt());
        long totalRequests = statistics.getTotalRequestCount();
        long clientErrors = statistics.getClientErrorCount();
        if (totalRequests < properties.getMinimumRequestCount()
                || !meetsRateThreshold(
                        clientErrors,
                        totalRequests,
                        properties.getClientErrorRateThresholdPercent())) {
            return;
        }

        String reason = ("Potential abnormal client-error-rate indicator: observed %d eligible client errors "
                + "among %d logged requests from one client IP within %d seconds; configured minimum sample "
                + "is %d requests and client-error-rate threshold is %d percent. Observed %d server errors "
                + "did not contribute to detection.")
                .formatted(
                        clientErrors,
                        totalRequests,
                        properties.getWindow().getSeconds(),
                        properties.getMinimumRequestCount(),
                        properties.getClientErrorRateThresholdPercent(),
                        statistics.getServerErrorCount());
        SecurityEventData eventData = new SecurityEventData(
                SecurityEventType.ABNORMAL_ERROR_RATE,
                RiskLevel.MEDIUM,
                event.requestedAt(),
                event.clientIp(),
                reason,
                event.requestLogId(),
                totalRequests,
                properties.getMinimumRequestCount(),
                properties.getWindow().getSeconds(),
                null,
                null,
                clientErrors,
                properties.getClientErrorRateThresholdPercent()
        );
        securityEventService.createIfNotSuppressed(eventData, properties.getSuppressionPeriod());
    }

    static boolean isEligibleClientError(int responseStatus) {
        return responseStatus >= 400 && responseStatus <= 499
                && responseStatus != 401
                && responseStatus != 403
                && responseStatus != 429;
    }

    static boolean meetsRateThreshold(long clientErrors, long totalRequests, int thresholdPercent) {
        if (clientErrors < 0 || totalRequests <= 0 || clientErrors > totalRequests
                || thresholdPercent < 1 || thresholdPercent > 100) {
            return false;
        }
        BigInteger observed = BigInteger.valueOf(clientErrors).multiply(BigInteger.valueOf(100));
        BigInteger required = BigInteger.valueOf(totalRequests).multiply(BigInteger.valueOf(thresholdPercent));
        return observed.compareTo(required) >= 0;
    }
}
