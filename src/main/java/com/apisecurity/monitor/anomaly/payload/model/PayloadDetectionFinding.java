package com.apisecurity.monitor.anomaly.payload.model;

import com.apisecurity.monitor.securityevent.model.SecurityEventType;

import java.util.Objects;

public record PayloadDetectionFinding(
        SecurityEventType eventType,
        InputLocation inputLocation,
        SignatureIdentifier signatureIdentifier
) {

    public PayloadDetectionFinding {
        Objects.requireNonNull(eventType, "Payload event type must not be null");
        Objects.requireNonNull(inputLocation, "Payload input location must not be null");
        Objects.requireNonNull(signatureIdentifier, "Payload signature identifier must not be null");
        if (signatureIdentifier.eventType() != eventType) {
            throw new IllegalArgumentException("Payload signature identifier does not match its event type");
        }
    }

    public enum InputLocation {
        QUERY_PARAMETER
    }

    public enum SignatureIdentifier {
        XSS_SCRIPT_TAG(SecurityEventType.XSS_ATTEMPT),
        XSS_EVENT_HANDLER(SecurityEventType.XSS_ATTEMPT),
        XSS_JAVASCRIPT_URI(SecurityEventType.XSS_ATTEMPT),
        SQLI_UNION_SELECT(SecurityEventType.SQL_INJECTION_ATTEMPT),
        SQLI_BOOLEAN_TAUTOLOGY(SecurityEventType.SQL_INJECTION_ATTEMPT);

        private final SecurityEventType eventType;

        SignatureIdentifier(SecurityEventType eventType) {
            this.eventType = eventType;
        }

        public SecurityEventType eventType() {
            return eventType;
        }
    }
}
