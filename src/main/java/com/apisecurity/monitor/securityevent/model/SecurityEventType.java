package com.apisecurity.monitor.securityevent.model;

public enum SecurityEventType {
    EXCESSIVE_REQUESTS,
    XSS_ATTEMPT,
    SQL_INJECTION_ATTEMPT,
    BRUTE_FORCE_ATTEMPT,
    ENDPOINT_SCANNING,
    ABNORMAL_ERROR_RATE
}
