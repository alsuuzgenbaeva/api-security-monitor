package com.apisecurity.monitor;

import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import static org.assertj.core.api.Assertions.assertThat;

class ApiSecurityMonitorApplicationTests {

	@Test
	void applicationIsConfiguredForSpringBoot() {
		assertThat(ApiSecurityMonitorApplication.class)
				.hasAnnotation(SpringBootApplication.class);
	}

}
