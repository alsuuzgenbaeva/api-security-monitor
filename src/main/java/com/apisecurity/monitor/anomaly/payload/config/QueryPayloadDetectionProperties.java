package com.apisecurity.monitor.anomaly.payload.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import java.time.Duration;

@Component
@ConfigurationProperties(prefix = "monitoring.anomaly-detection.query-payload")
public class QueryPayloadDetectionProperties {

    private static final int MAX_CONFIGURABLE_QUERY_LENGTH = 32_768;
    private static final int MAX_CONFIGURABLE_PARAMETER_LENGTH = 4_096;
    private static final int MAX_CONFIGURABLE_PARAMETER_COUNT = 100;

    private boolean enabled = true;
    private int maxQueryLength = 8_192;
    private int maxParameterLength = 2_048;
    private int maxParameters = 50;
    private Duration suppressionPeriod = Duration.ofSeconds(30);

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public int getMaxQueryLength() {
        return maxQueryLength;
    }

    public void setMaxQueryLength(int maxQueryLength) {
        this.maxQueryLength = requireBoundedPositive(
                maxQueryLength, MAX_CONFIGURABLE_QUERY_LENGTH, "Query payload maximum query length");
    }

    public int getMaxParameterLength() {
        return maxParameterLength;
    }

    public void setMaxParameterLength(int maxParameterLength) {
        this.maxParameterLength = requireBoundedPositive(
                maxParameterLength, MAX_CONFIGURABLE_PARAMETER_LENGTH, "Query payload maximum parameter length");
    }

    public int getMaxParameters() {
        return maxParameters;
    }

    public void setMaxParameters(int maxParameters) {
        this.maxParameters = requireBoundedPositive(
                maxParameters, MAX_CONFIGURABLE_PARAMETER_COUNT, "Query payload maximum parameter count");
    }

    public Duration getSuppressionPeriod() {
        return suppressionPeriod;
    }

    public void setSuppressionPeriod(Duration suppressionPeriod) {
        if (suppressionPeriod == null || suppressionPeriod.isZero()
                || suppressionPeriod.isNegative() || suppressionPeriod.getSeconds() < 1) {
            throw new IllegalArgumentException("Query payload suppression period must be at least one second");
        }
        this.suppressionPeriod = suppressionPeriod;
    }

    private int requireBoundedPositive(int value, int maximum, String name) {
        if (value < 1 || value > maximum) {
            throw new IllegalArgumentException(name + " must be between 1 and " + maximum);
        }
        return value;
    }
}
