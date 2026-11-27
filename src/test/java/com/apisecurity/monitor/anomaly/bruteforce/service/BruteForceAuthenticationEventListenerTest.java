package com.apisecurity.monitor.anomaly.bruteforce.service;

import com.apisecurity.monitor.anomaly.bruteforce.config.BruteForceDetectionProperties;
import com.apisecurity.monitor.securityevent.model.RiskLevel;
import com.apisecurity.monitor.securityevent.model.SecurityEventData;
import com.apisecurity.monitor.securityevent.model.SecurityEventType;
import com.apisecurity.monitor.securityevent.service.SecurityEventService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.event.AuthenticationFailureBadCredentialsEvent;
import org.springframework.security.authentication.event.AuthenticationSuccessEvent;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.web.authentication.WebAuthenticationDetails;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class BruteForceAuthenticationEventListenerTest {

    private static final Instant NOW = Instant.parse("2026-11-27T08:00:00Z");

    @Mock
    private SecurityEventService securityEventService;

    private BruteForceDetectionProperties properties;
    private BruteForceAuthenticationEventListener listener;

    @BeforeEach
    void setUp() {
        properties = new BruteForceDetectionProperties();
        properties.setThreshold(2);
        BruteForceAttemptTracker tracker = new BruteForceAttemptTracker(
                properties,
                Clock.fixed(NOW, ZoneOffset.UTC),
                new byte[32]);
        listener = new BruteForceAuthenticationEventListener(properties, tracker, securityEventService);
    }

    @Test
    void createsPrivacySafeHighRiskEventAtThreshold() {
        listener.processFailure(failedAuthentication("192.0.2.10", "admin", "session-sensitive"));
        listener.processFailure(failedAuthentication("192.0.2.10", "other-user", "another-session"));

        ArgumentCaptor<SecurityEventData> captor = ArgumentCaptor.forClass(SecurityEventData.class);
        verify(securityEventService).createIfNotSuppressed(captor.capture(), any(Duration.class));
        SecurityEventData data = captor.getValue();
        assertThat(data.eventType()).isEqualTo(SecurityEventType.BRUTE_FORCE_ATTEMPT);
        assertThat(data.riskLevel()).isEqualTo(RiskLevel.HIGH);
        assertThat(data.occurredAt()).isEqualTo(NOW);
        assertThat(data.clientIp()).isEqualTo("192.0.2.10");
        assertThat(data.sourceRequestLogId()).isNull();
        assertThat(data.observedRequestCount()).isEqualTo(2);
        assertThat(data.configuredThreshold()).isEqualTo(2);
        assertThat(data.windowSeconds()).isEqualTo(60);
        assertThat(data.detectionReason())
                .contains("Potential brute-force indicator", "2", "60")
                .doesNotContain("admin", "other-user", "password-sensitive", "session-sensitive");
        verify(securityEventService).createIfNotSuppressed(data, Duration.ofSeconds(60));
    }

    @Test
    void successfulAuthenticationClearsOnlyTheMatchingAccount() {
        properties.setThreshold(3);
        listener.processFailure(failedAuthentication("192.0.2.10", "admin", "session-1"));
        listener.processFailure(failedAuthentication("192.0.2.10", "other-user", "session-2"));
        listener.processSuccess(successfulAuthentication("192.0.2.10", "admin", "session-3"));
        listener.processFailure(failedAuthentication("192.0.2.10", "third-user", "session-4"));
        listener.processFailure(failedAuthentication("192.0.2.10", "fourth-user", "session-5"));

        ArgumentCaptor<SecurityEventData> captor = ArgumentCaptor.forClass(SecurityEventData.class);
        verify(securityEventService).createIfNotSuppressed(captor.capture(), any(Duration.class));
        assertThat(captor.getValue().observedRequestCount()).isEqualTo(3);
    }

    @Test
    void ignoresNonWebAndUnexpectedAuthenticationStates() {
        Authentication withoutWebDetails = UsernamePasswordAuthenticationToken.unauthenticated(
                "admin", "password-sensitive");
        listener.processFailure(withoutWebDetails);
        listener.processFailure(successfulAuthentication("192.0.2.10", "admin", "session"));
        listener.processSuccess(failedAuthentication("192.0.2.10", "admin", "session"));

        verify(securityEventService, never()).createIfNotSuppressed(any(), any());
    }

    @Test
    void disabledDetectionDoesNotTrackFailures() {
        properties.setEnabled(false);

        listener.processFailure(failedAuthentication("192.0.2.10", "admin", "session"));
        listener.processFailure(failedAuthentication("192.0.2.10", "admin", "session"));

        verify(securityEventService, never()).createIfNotSuppressed(any(), any());
    }

    @Test
    void persistenceFailureCannotEscapeAuthenticationEventListener() {
        when(securityEventService.createIfNotSuppressed(any(), any()))
                .thenThrow(new IllegalStateException("database unavailable"));
        listener.onAuthenticationFailure(new AuthenticationFailureBadCredentialsEvent(
                failedAuthentication("192.0.2.10", "admin", "session-1"),
                new BadCredentialsException("bad credentials")));

        assertThatCode(() -> listener.onAuthenticationFailure(new AuthenticationFailureBadCredentialsEvent(
                failedAuthentication("192.0.2.10", "admin", "session-2"),
                new BadCredentialsException("bad credentials"))))
                .doesNotThrowAnyException();
    }

    @Test
    void trackerFailureCannotEscapeSuccessfulAuthenticationListener() {
        BruteForceAttemptTracker failingTracker = mock(BruteForceAttemptTracker.class);
        doThrow(new IllegalStateException("tracker unavailable"))
                .when(failingTracker).recordSuccess(any(), any());
        BruteForceAuthenticationEventListener failingListener = new BruteForceAuthenticationEventListener(
                properties, failingTracker, securityEventService);

        assertThatCode(() -> failingListener.onAuthenticationSuccess(new AuthenticationSuccessEvent(
                successfulAuthentication("192.0.2.10", "admin", "session"))))
                .doesNotThrowAnyException();
    }

    private Authentication failedAuthentication(String remoteAddress, String account, String sessionId) {
        UsernamePasswordAuthenticationToken authentication =
                UsernamePasswordAuthenticationToken.unauthenticated(account, "password-sensitive");
        authentication.setDetails(new WebAuthenticationDetails(remoteAddress, sessionId));
        return authentication;
    }

    private Authentication successfulAuthentication(String remoteAddress, String account, String sessionId) {
        UsernamePasswordAuthenticationToken authentication = UsernamePasswordAuthenticationToken.authenticated(
                account,
                "password-sensitive",
                List.of(new SimpleGrantedAuthority("ROLE_ADMIN")));
        authentication.setDetails(new WebAuthenticationDetails(remoteAddress, sessionId));
        return authentication;
    }
}
