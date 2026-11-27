package com.apisecurity.monitor.anomaly.bruteforce.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.stereotype.Component;

import java.time.Duration;

@Component
@ConfigurationProperties(prefix = "monitoring.anomaly-detection.brute-force")
public class BruteForceDetectionProperties implements InitializingBean {

    private static final int MAX_THRESHOLD = 100;
    private static final int MAX_CLIENT_CAPACITY = 10_000;
    private static final int MAX_HISTORY_CAPACITY = 1_000;
    private static final Duration MAX_DURATION = Duration.ofHours(24);

    private boolean enabled = true;
    private int threshold = 5;
    private Duration window = Duration.ofSeconds(60);
    private Duration suppressionPeriod = Duration.ofSeconds(60);
    private int maxTrackedClients = 1_000;
    private int maxAttemptsPerClient = 100;

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public int getThreshold() {
        return threshold;
    }

    public void setThreshold(int threshold) {
        if (threshold < 2 || threshold > MAX_THRESHOLD) {
            throw new IllegalArgumentException("Brute-force threshold must be between 2 and " + MAX_THRESHOLD);
        }
        this.threshold = threshold;
    }

    public Duration getWindow() {
        return window;
    }

    public void setWindow(Duration window) {
        this.window = requireBoundedDuration(window, "Brute-force window");
    }

    public Duration getSuppressionPeriod() {
        return suppressionPeriod;
    }

    public void setSuppressionPeriod(Duration suppressionPeriod) {
        this.suppressionPeriod = requireBoundedDuration(suppressionPeriod, "Brute-force suppression period");
    }

    public int getMaxTrackedClients() {
        return maxTrackedClients;
    }

    public void setMaxTrackedClients(int maxTrackedClients) {
        if (maxTrackedClients < 1 || maxTrackedClients > MAX_CLIENT_CAPACITY) {
            throw new IllegalArgumentException(
                    "Brute-force tracked-client capacity must be between 1 and " + MAX_CLIENT_CAPACITY);
        }
        this.maxTrackedClients = maxTrackedClients;
    }

    public int getMaxAttemptsPerClient() {
        return maxAttemptsPerClient;
    }

    public void setMaxAttemptsPerClient(int maxAttemptsPerClient) {
        if (maxAttemptsPerClient < 2 || maxAttemptsPerClient > MAX_HISTORY_CAPACITY) {
            throw new IllegalArgumentException(
                    "Brute-force per-client history capacity must be between 2 and " + MAX_HISTORY_CAPACITY);
        }
        this.maxAttemptsPerClient = maxAttemptsPerClient;
    }

    @Override
    public void afterPropertiesSet() {
        if (threshold > maxAttemptsPerClient) {
            throw new IllegalArgumentException("Brute-force threshold must not exceed per-client history capacity");
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
