package com.apisecurity.monitor.anomaly.bruteforce.service;

import com.apisecurity.monitor.anomaly.bruteforce.config.BruteForceDetectionProperties;
import com.apisecurity.monitor.securityevent.model.RiskLevel;
import com.apisecurity.monitor.securityevent.model.SecurityEventData;
import com.apisecurity.monitor.securityevent.model.SecurityEventType;
import com.apisecurity.monitor.securityevent.service.SecurityEventService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.event.EventListener;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.event.AuthenticationFailureBadCredentialsEvent;
import org.springframework.security.authentication.event.AuthenticationSuccessEvent;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.WebAuthenticationDetails;
import org.springframework.stereotype.Component;

import java.util.Optional;

@Component
public class BruteForceAuthenticationEventListener {

    private static final Logger logger = LoggerFactory.getLogger(BruteForceAuthenticationEventListener.class);
    private static final int MAX_IP_LENGTH = 45;

    private final BruteForceDetectionProperties properties;
    private final BruteForceAttemptTracker tracker;
    private final SecurityEventService securityEventService;

    public BruteForceAuthenticationEventListener(
            BruteForceDetectionProperties properties,
            BruteForceAttemptTracker tracker,
            SecurityEventService securityEventService
    ) {
        this.properties = properties;
        this.tracker = tracker;
        this.securityEventService = securityEventService;
    }

    @EventListener
    public void onAuthenticationFailure(AuthenticationFailureBadCredentialsEvent event) {
        try {
            processFailure(event.getAuthentication());
        } catch (RuntimeException detectionFailure) {
            logger.error("Brute-force failure processing failed; authentication behavior is unchanged");
        }
    }

    @EventListener
    public void onAuthenticationSuccess(AuthenticationSuccessEvent event) {
        try {
            processSuccess(event.getAuthentication());
        } catch (RuntimeException detectionFailure) {
            logger.error("Brute-force success processing failed; authentication behavior is unchanged");
        }
    }

    void processFailure(Authentication authentication) {
        if (!properties.isEnabled()) {
            return;
        }
        authenticationIdentity(authentication, false).ifPresent(identity -> {
            BruteForceAttemptTracker.FailureObservation observation =
                    tracker.recordFailure(identity.clientIp(), identity.accountIdentifier());
            if (!observation.tracked() || observation.observedCount() < properties.getThreshold()) {
                return;
            }

            String reason = ("Potential brute-force indicator: observed at least %d failed username/password "
                    + "authentication attempts from one client IP within %d seconds; configured threshold is %d.")
                    .formatted(
                            observation.observedCount(),
                            properties.getWindow().getSeconds(),
                            properties.getThreshold());
            SecurityEventData eventData = new SecurityEventData(
                    SecurityEventType.BRUTE_FORCE_ATTEMPT,
                    RiskLevel.HIGH,
                    observation.occurredAt(),
                    identity.clientIp(),
                    reason,
                    null,
                    observation.observedCount(),
                    properties.getThreshold(),
                    properties.getWindow().getSeconds()
            );
            securityEventService.createIfNotSuppressed(eventData, properties.getSuppressionPeriod());
        });
    }

    void processSuccess(Authentication authentication) {
        if (!properties.isEnabled()) {
            return;
        }
        authenticationIdentity(authentication, true).ifPresent(identity ->
                tracker.recordSuccess(identity.clientIp(), identity.accountIdentifier()));
    }

    private Optional<AuthenticationIdentity> authenticationIdentity(
            Authentication authentication,
            boolean expectedAuthenticatedState
    ) {
        if (!(authentication instanceof UsernamePasswordAuthenticationToken)
                || authentication.isAuthenticated() != expectedAuthenticatedState
                || !(authentication.getDetails() instanceof WebAuthenticationDetails details)) {
            return Optional.empty();
        }

        String clientIp = details.getRemoteAddress();
        String accountIdentifier = authentication.getName();
        if (clientIp == null || clientIp.isBlank() || clientIp.length() > MAX_IP_LENGTH
                || accountIdentifier == null) {
            return Optional.empty();
        }
        return Optional.of(new AuthenticationIdentity(clientIp, accountIdentifier));
    }

    private record AuthenticationIdentity(String clientIp, String accountIdentifier) {
    }
}
