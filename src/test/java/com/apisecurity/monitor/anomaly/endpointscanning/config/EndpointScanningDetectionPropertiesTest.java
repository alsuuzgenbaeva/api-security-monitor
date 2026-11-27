package com.apisecurity.monitor.anomaly.endpointscanning.config;

import org.junit.jupiter.api.Test;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.annotation.Configuration;

import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class EndpointScanningDetectionPropertiesTest {

    private static final String PREFIX = "monitoring.anomaly-detection.endpoint-scanning.";
    private final ApplicationContextRunner contextRunner = new ApplicationContextRunner()
            .withUserConfiguration(TestConfiguration.class);

    @Test
    void exposesBoundedDefaults() {
        EndpointScanningDetectionProperties properties = new EndpointScanningDetectionProperties();

        assertThat(properties.isEnabled()).isTrue();
        assertThat(properties.getDistinctPathThreshold()).isEqualTo(5);
        assertThat(properties.getMinimumUnsuccessfulRequests()).isEqualTo(8);
        assertThat(properties.getWindow()).isEqualTo(Duration.ofSeconds(60));
        assertThat(properties.getSuppressionPeriod()).isEqualTo(Duration.ofSeconds(60));
    }

    @Test
    void rejectsIndependentUnsafeLimits() {
        EndpointScanningDetectionProperties properties = new EndpointScanningDetectionProperties();

        assertThatThrownBy(() -> properties.setDistinctPathThreshold(1))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> properties.setDistinctPathThreshold(1_001))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> properties.setMinimumUnsuccessfulRequests(1))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> properties.setMinimumUnsuccessfulRequests(10_001))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> properties.setWindow(Duration.ZERO))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> properties.setSuppressionPeriod(Duration.ofHours(25)))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void acceptsValidCrossPropertyValuesInEitherBindingOrder() {
        contextRunner.withPropertyValues(
                        PREFIX + "minimum-unsuccessful-requests=4",
                        PREFIX + "distinct-path-threshold=3")
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    EndpointScanningDetectionProperties properties =
                            context.getBean(EndpointScanningDetectionProperties.class);
                    assertThat(properties.getDistinctPathThreshold()).isEqualTo(3);
                    assertThat(properties.getMinimumUnsuccessfulRequests()).isEqualTo(4);
                });

        contextRunner.withPropertyValues(
                        PREFIX + "distinct-path-threshold=3",
                        PREFIX + "minimum-unsuccessful-requests=4")
                .run(context -> assertThat(context).hasNotFailed());
    }

    @Test
    void rejectsInvalidFinalCrossPropertyConfigurationAfterBinding() {
        contextRunner.withPropertyValues(
                        PREFIX + "minimum-unsuccessful-requests=4",
                        PREFIX + "distinct-path-threshold=5")
                .run(context -> {
                    assertThat(context).hasFailed();
                    assertThat(context.getStartupFailure())
                            .hasRootCauseInstanceOf(IllegalArgumentException.class)
                            .hasRootCauseMessage(
                                    "Endpoint-scanning minimum unsuccessful requests must not be less than "
                                            + "distinct-path threshold");
                });
    }

    @Configuration(proxyBeanMethods = false)
    @EnableConfigurationProperties(EndpointScanningDetectionProperties.class)
    static class TestConfiguration {
    }
}
