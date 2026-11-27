package com.apisecurity.monitor.anomaly.errorrate.config;

import org.junit.jupiter.api.Test;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.annotation.Configuration;

import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class AbnormalErrorRateDetectionPropertiesTest {

    private static final String PREFIX = "monitoring.anomaly-detection.abnormal-error-rate.";
    private final ApplicationContextRunner contextRunner = new ApplicationContextRunner()
            .withUserConfiguration(TestConfiguration.class);

    @Test
    void exposesBoundedDefaults() {
        AbnormalErrorRateDetectionProperties properties = new AbnormalErrorRateDetectionProperties();

        assertThat(properties.isEnabled()).isTrue();
        assertThat(properties.getMinimumRequestCount()).isEqualTo(10);
        assertThat(properties.getClientErrorRateThresholdPercent()).isEqualTo(60);
        assertThat(properties.getWindow()).isEqualTo(Duration.ofSeconds(60));
        assertThat(properties.getSuppressionPeriod()).isEqualTo(Duration.ofSeconds(60));
    }

    @Test
    void rejectsUnsafeLimitsAndAcceptsIndependentValidValues() {
        AbnormalErrorRateDetectionProperties properties = new AbnormalErrorRateDetectionProperties();

        assertThatThrownBy(() -> properties.setMinimumRequestCount(1))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> properties.setMinimumRequestCount(100_001))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> properties.setClientErrorRateThresholdPercent(0))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> properties.setClientErrorRateThresholdPercent(101))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> properties.setWindow(null))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> properties.setSuppressionPeriod(Duration.ofHours(25)))
                .isInstanceOf(IllegalArgumentException.class);

        properties.setClientErrorRateThresholdPercent(75);
        properties.setMinimumRequestCount(20);
        assertThat(properties.getClientErrorRateThresholdPercent()).isEqualTo(75);
        assertThat(properties.getMinimumRequestCount()).isEqualTo(20);
    }

    @Test
    void bindsValidIndependentValuesInEitherPropertyOrder() {
        contextRunner.withPropertyValues(
                        PREFIX + "minimum-request-count=20",
                        PREFIX + "client-error-rate-threshold-percent=75")
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    AbnormalErrorRateDetectionProperties properties =
                            context.getBean(AbnormalErrorRateDetectionProperties.class);
                    assertThat(properties.getMinimumRequestCount()).isEqualTo(20);
                    assertThat(properties.getClientErrorRateThresholdPercent()).isEqualTo(75);
                });

        contextRunner.withPropertyValues(
                        PREFIX + "client-error-rate-threshold-percent=75",
                        PREFIX + "minimum-request-count=20")
                .run(context -> assertThat(context).hasNotFailed());
    }

    @Test
    void invalidBoundConfigurationFailsContextStartup() {
        contextRunner.withPropertyValues(PREFIX + "client-error-rate-threshold-percent=101")
                .run(context -> assertThat(context).hasFailed());
    }

    @Configuration(proxyBeanMethods = false)
    @EnableConfigurationProperties(AbnormalErrorRateDetectionProperties.class)
    static class TestConfiguration {
    }
}
