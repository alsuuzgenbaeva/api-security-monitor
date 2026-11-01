package com.apisecurity.monitor.anomaly.excessiverequests.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import java.time.Duration;

@Component
@ConfigurationProperties(prefix = "monitoring.anomaly-detection.excessive-requests")
public class ExcessiveRequestRuleProperties {

    private boolean enabled = true;
    private int threshold = 5;
    private Duration window = Duration.ofSeconds(10);
    private Duration suppressionPeriod = Duration.ofSeconds(30);

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
        if (threshold < 1) {
            throw new IllegalArgumentException("Excessive-request threshold must be positive");
        }
        this.threshold = threshold;
    }

    public Duration getWindow() {
        return window;
    }

    public void setWindow(Duration window) {
        this.window = requirePositive(window, "Excessive-request window");
    }

    public Duration getSuppressionPeriod() {
        return suppressionPeriod;
    }

    public void setSuppressionPeriod(Duration suppressionPeriod) {
        this.suppressionPeriod = requirePositive(suppressionPeriod, "Excessive-request suppression period");
    }

    private Duration requirePositive(Duration value, String name) {
        if (value == null || value.isZero() || value.isNegative() || value.getSeconds() < 1) {
            throw new IllegalArgumentException(name + " must be at least one second");
        }
        return value;
    }
}
