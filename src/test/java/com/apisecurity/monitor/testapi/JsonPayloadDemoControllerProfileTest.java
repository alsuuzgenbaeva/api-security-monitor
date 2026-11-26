package com.apisecurity.monitor.testapi;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;

import static org.assertj.core.api.Assertions.assertThat;

class JsonPayloadDemoControllerProfileTest {

    private final ApplicationContextRunner contextRunner = new ApplicationContextRunner()
            .withUserConfiguration(DemoControllerConfiguration.class);

    @Test
    void controllerIsAbsentWithoutAnExplicitDemoProfile() {
        contextRunner.run(context -> assertThat(context)
                .doesNotHaveBean(JsonPayloadDemoController.class));
    }

    @Test
    void controllerIsAvailableWithDemoProfile() {
        contextRunner
                .withInitializer(context -> context.getEnvironment().setActiveProfiles("demo"))
                .run(context -> assertThat(context)
                        .hasSingleBean(JsonPayloadDemoController.class));
    }

    @Configuration(proxyBeanMethods = false)
    @Import(JsonPayloadDemoController.class)
    static class DemoControllerConfiguration {
    }
}
