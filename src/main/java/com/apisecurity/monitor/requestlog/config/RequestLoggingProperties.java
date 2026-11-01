package com.apisecurity.monitor.requestlog.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import java.util.LinkedHashSet;
import java.util.Set;

@Component
@ConfigurationProperties(prefix = "monitoring.request-logging")
public class RequestLoggingProperties {

    private boolean enabled = true;
    private Set<String> excludedPaths = new LinkedHashSet<>(Set.of("/error", "/favicon.ico"));

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public Set<String> getExcludedPaths() {
        return excludedPaths;
    }

    public void setExcludedPaths(Set<String> excludedPaths) {
        this.excludedPaths = excludedPaths == null ? new LinkedHashSet<>() : new LinkedHashSet<>(excludedPaths);
    }
}
