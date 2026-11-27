package com.apisecurity.monitor.anomaly.endpointscanning.config;

import org.springframework.beans.factory.InitializingBean;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import java.time.Duration;

@Component
@ConfigurationProperties(prefix = "monitoring.anomaly-detection.endpoint-scanning")
public class EndpointScanningDetectionProperties implements InitializingBean {

    private static final int MAX_DISTINCT_PATH_THRESHOLD = 1_000;
    private static final int MAX_REQUEST_THRESHOLD = 10_000;
    private static final Duration MAX_DURATION = Duration.ofHours(24);

    private boolean enabled = true;
    private int distinctPathThreshold = 5;
    private int minimumUnsuccessfulRequests = 8;
    private Duration window = Duration.ofSeconds(60);
    private Duration suppressionPeriod = Duration.ofSeconds(60);

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public int getDistinctPathThreshold() {
        return distinctPathThreshold;
    }

    public void setDistinctPathThreshold(int distinctPathThreshold) {
        if (distinctPathThreshold < 2 || distinctPathThreshold > MAX_DISTINCT_PATH_THRESHOLD) {
            throw new IllegalArgumentException(
                    "Endpoint-scanning distinct-path threshold must be between 2 and "
                            + MAX_DISTINCT_PATH_THRESHOLD);
        }
        this.distinctPathThreshold = distinctPathThreshold;
    }

    public int getMinimumUnsuccessfulRequests() {
        return minimumUnsuccessfulRequests;
    }

    public void setMinimumUnsuccessfulRequests(int minimumUnsuccessfulRequests) {
        if (minimumUnsuccessfulRequests < 2 || minimumUnsuccessfulRequests > MAX_REQUEST_THRESHOLD) {
            throw new IllegalArgumentException(
                    "Endpoint-scanning minimum unsuccessful requests must be between 2 and "
                            + MAX_REQUEST_THRESHOLD);
        }
        this.minimumUnsuccessfulRequests = minimumUnsuccessfulRequests;
    }

    public Duration getWindow() {
        return window;
    }

    public void setWindow(Duration window) {
        this.window = requireBoundedDuration(window, "Endpoint-scanning window");
    }

    public Duration getSuppressionPeriod() {
        return suppressionPeriod;
    }

    public void setSuppressionPeriod(Duration suppressionPeriod) {
        this.suppressionPeriod = requireBoundedDuration(
                suppressionPeriod, "Endpoint-scanning suppression period");
    }

    @Override
    public void afterPropertiesSet() {
        if (minimumUnsuccessfulRequests < distinctPathThreshold) {
            throw new IllegalArgumentException(
                    "Endpoint-scanning minimum unsuccessful requests must not be less than distinct-path threshold");
        }
    }

    private Duration requireBoundedDuration(Duration value, String name) {
        if (value == null || value.isZero() || value.isNegative()
                || value.getSeconds() < 1 || value.compareTo(MAX_DURATION) > 0) {
            throw new IllegalArgumentException(name + " must be between one second and 24 hours");
        }
        return value;
    }
}
