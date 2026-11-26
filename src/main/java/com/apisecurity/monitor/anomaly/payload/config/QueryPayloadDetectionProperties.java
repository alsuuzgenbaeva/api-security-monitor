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
    private static final int MAX_CONFIGURABLE_PATH_LENGTH = 2_048;
    private static final int MAX_CONFIGURABLE_BODY_CACHE_BYTES = 65_536;
    private static final int MAX_CONFIGURABLE_JSON_DEPTH = 256;
    private static final int MAX_CONFIGURABLE_JSON_VALUE_COUNT = 100;
    private static final int MAX_CONFIGURABLE_JSON_STRING_LENGTH = 4_096;

    private boolean enabled = true;
    private int maxQueryLength = 8_192;
    private int maxParameterLength = 2_048;
    private int maxParameters = 50;
    private int maxPathLength = 2_048;
    private int maxBodyCacheBytes = 16_384;
    private int maxJsonDepth = 64;
    private int maxJsonValues = 50;
    private int maxJsonStringLength = 2_048;
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

    public int getMaxPathLength() {
        return maxPathLength;
    }

    public void setMaxPathLength(int maxPathLength) {
        this.maxPathLength = requireBoundedPositive(
                maxPathLength, MAX_CONFIGURABLE_PATH_LENGTH, "Payload maximum path length");
    }

    public int getMaxBodyCacheBytes() {
        return maxBodyCacheBytes;
    }

    public void setMaxBodyCacheBytes(int maxBodyCacheBytes) {
        this.maxBodyCacheBytes = requireBoundedPositive(
                maxBodyCacheBytes, MAX_CONFIGURABLE_BODY_CACHE_BYTES, "Payload maximum body cache bytes");
    }

    public int getMaxJsonDepth() {
        return maxJsonDepth;
    }

    public void setMaxJsonDepth(int maxJsonDepth) {
        this.maxJsonDepth = requireBoundedPositive(
                maxJsonDepth, MAX_CONFIGURABLE_JSON_DEPTH, "Payload maximum JSON depth");
    }

    public int getMaxJsonValues() {
        return maxJsonValues;
    }

    public void setMaxJsonValues(int maxJsonValues) {
        this.maxJsonValues = requireBoundedPositive(
                maxJsonValues, MAX_CONFIGURABLE_JSON_VALUE_COUNT, "Payload maximum JSON value count");
    }

    public int getMaxJsonStringLength() {
        return maxJsonStringLength;
    }

    public void setMaxJsonStringLength(int maxJsonStringLength) {
        this.maxJsonStringLength = requireBoundedPositive(
                maxJsonStringLength,
                MAX_CONFIGURABLE_JSON_STRING_LENGTH,
                "Payload maximum JSON string length");
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
