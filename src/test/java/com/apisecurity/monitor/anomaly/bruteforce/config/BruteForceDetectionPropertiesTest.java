package com.apisecurity.monitor.anomaly.bruteforce.config;

import org.junit.jupiter.api.Test;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.annotation.Configuration;

import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class BruteForceDetectionPropertiesTest {

    private static final String PREFIX = "monitoring.anomaly-detection.brute-force.";
    private final ApplicationContextRunner contextRunner = new ApplicationContextRunner()
            .withUserConfiguration(TestConfiguration.class);

    @Test
    void exposesBoundedDemonstrationDefaults() {
        BruteForceDetectionProperties properties = new BruteForceDetectionProperties();

        assertThat(properties.isEnabled()).isTrue();
        assertThat(properties.getThreshold()).isEqualTo(5);
        assertThat(properties.getWindow()).isEqualTo(Duration.ofSeconds(60));
        assertThat(properties.getSuppressionPeriod()).isEqualTo(Duration.ofSeconds(60));
        assertThat(properties.getMaxTrackedClients()).isEqualTo(1_000);
        assertThat(properties.getMaxAttemptsPerClient()).isEqualTo(100);
    }

    @Test
    void rejectsUnsafeConfigurationLimits() {
        BruteForceDetectionProperties properties = new BruteForceDetectionProperties();

        assertThatThrownBy(() -> properties.setThreshold(1)).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> properties.setThreshold(101)).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> properties.setWindow(Duration.ZERO)).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> properties.setWindow(Duration.ofHours(25)))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> properties.setSuppressionPeriod(null))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> properties.setMaxTrackedClients(0))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> properties.setMaxTrackedClients(10_001))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> properties.setMaxAttemptsPerClient(1))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> properties.setMaxAttemptsPerClient(1_001))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void acceptsValidCrossPropertyValuesInEitherBindingOrder() {
        contextRunner.withPropertyValues(
                        PREFIX + "max-attempts-per-client=3",
                        PREFIX + "threshold=2")
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    BruteForceDetectionProperties properties =
                            context.getBean(BruteForceDetectionProperties.class);
                    assertThat(properties.getThreshold()).isEqualTo(2);
                    assertThat(properties.getMaxAttemptsPerClient()).isEqualTo(3);
                });

        contextRunner.withPropertyValues(
                        PREFIX + "threshold=2",
                        PREFIX + "max-attempts-per-client=3")
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    BruteForceDetectionProperties properties =
                            context.getBean(BruteForceDetectionProperties.class);
                    assertThat(properties.getThreshold()).isEqualTo(2);
                    assertThat(properties.getMaxAttemptsPerClient()).isEqualTo(3);
                });
    }

    @Test
    void rejectsInvalidFinalCrossPropertyConfigurationAfterBinding() {
        contextRunner.withPropertyValues(
                        PREFIX + "max-attempts-per-client=3",
                        PREFIX + "threshold=4")
                .run(context -> {
                    assertThat(context).hasFailed();
                    assertThat(context.getStartupFailure())
                            .hasRootCauseInstanceOf(IllegalArgumentException.class)
                            .hasRootCauseMessage(
                                    "Brute-force threshold must not exceed per-client history capacity");
                });
    }

    @Configuration(proxyBeanMethods = false)
    @EnableConfigurationProperties(BruteForceDetectionProperties.class)
    static class TestConfiguration {
    }
}
