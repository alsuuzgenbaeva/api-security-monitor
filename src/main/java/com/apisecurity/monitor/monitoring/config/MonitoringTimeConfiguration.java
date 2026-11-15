package com.apisecurity.monitor.monitoring.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.time.Clock;

@Configuration(proxyBeanMethods = false)
public class MonitoringTimeConfiguration {

    @Bean
    Clock monitoringClock() {
        return Clock.systemUTC();
    }
}
