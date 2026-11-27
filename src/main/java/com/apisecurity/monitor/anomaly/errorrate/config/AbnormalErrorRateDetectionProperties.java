package com.apisecurity.monitor.anomaly.errorrate.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import java.time.Duration;

@Component
@ConfigurationProperties(prefix = "monitoring.anomaly-detection.abnormal-error-rate")
public class AbnormalErrorRateDetectionProperties {

    private static final int MAX_MINIMUM_REQUEST_COUNT = 100_000;
    private static final Duration MAX_DURATION = Duration.ofHours(24);

    private boolean enabled = true;
    private int minimumRequestCount = 10;
    private int clientErrorRateThresholdPercent = 60;
    private Duration window = Duration.ofSeconds(60);
    private Duration suppressionPeriod = Duration.ofSeconds(60);

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public int getMinimumRequestCount() {
        return minimumRequestCount;
    }

    public void setMinimumRequestCount(int minimumRequestCount) {
        if (minimumRequestCount < 2 || minimumRequestCount > MAX_MINIMUM_REQUEST_COUNT) {
            throw new IllegalArgumentException(
                    "Abnormal-error-rate minimum request count must be between 2 and "
                            + MAX_MINIMUM_REQUEST_COUNT);
        }
        this.minimumRequestCount = minimumRequestCount;
    }

    public int getClientErrorRateThresholdPercent() {
        return clientErrorRateThresholdPercent;
    }

    public void setClientErrorRateThresholdPercent(int clientErrorRateThresholdPercent) {
        if (clientErrorRateThresholdPercent < 1 || clientErrorRateThresholdPercent > 100) {
            throw new IllegalArgumentException(
                    "Abnormal-error-rate client-error threshold must be between 1 and 100 percent");
        }
        this.clientErrorRateThresholdPercent = clientErrorRateThresholdPercent;
    }

    public Duration getWindow() {
        return window;
    }

    public void setWindow(Duration window) {
        this.window = requireBoundedDuration(window, "Abnormal-error-rate window");
    }

    public Duration getSuppressionPeriod() {
        return suppressionPeriod;
    }

    public void setSuppressionPeriod(Duration suppressionPeriod) {
        this.suppressionPeriod = requireBoundedDuration(
                suppressionPeriod, "Abnormal-error-rate suppression period");
    }

    private Duration requireBoundedDuration(Duration value, String name) {
        if (value == null || value.isZero() || value.isNegative()
                || value.getSeconds() < 1 || value.compareTo(MAX_DURATION) > 0) {
            throw new IllegalArgumentException(name + " must be between one second and 24 hours");
        }
        return value;
    }
}
