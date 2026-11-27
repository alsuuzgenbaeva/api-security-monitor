package com.apisecurity.monitor.anomaly.bruteforce.service;

import com.apisecurity.monitor.anomaly.bruteforce.config.BruteForceDetectionProperties;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Instant;
import java.util.ArrayDeque;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Locale;
import java.util.Map;

@Component
public class BruteForceAttemptTracker {

    private static final String HMAC_ALGORITHM = "HmacSHA256";
    private static final int HMAC_KEY_BYTES = 32;
    private static final int MAX_ACCOUNT_IDENTIFIER_CHARACTERS = 256;

    private final BruteForceDetectionProperties properties;
    private final Clock clock;
    private final byte[] fingerprintKey;
    private final Map<String, ClientHistory> histories = new HashMap<>();

    @Autowired
    public BruteForceAttemptTracker(BruteForceDetectionProperties properties, Clock clock) {
        this(properties, clock, createFingerprintKey());
    }

    BruteForceAttemptTracker(
            BruteForceDetectionProperties properties,
            Clock clock,
            byte[] fingerprintKey
    ) {
        this.properties = properties;
        this.clock = clock;
        this.fingerprintKey = Arrays.copyOf(fingerprintKey, fingerprintKey.length);
    }

    public synchronized FailureObservation recordFailure(String clientIp, String accountIdentifier) {
        Instant now = clock.instant();
        ClientHistory history = histories.get(clientIp);
        if (history == null) {
            removeExpiredHistories(now);
            if (histories.size() >= properties.getMaxTrackedClients()) {
                return FailureObservation.notTracked(now);
            }
            history = new ClientHistory();
            histories.put(clientIp, history);
        }

        prune(history, now);
        if (history.isSaturatedAt(now)) {
            history.saturatedUntil = now.plus(properties.getWindow());
            return new FailureObservation(now, properties.getMaxAttemptsPerClient(), true, true);
        }

        if (history.attempts.size() >= properties.getMaxAttemptsPerClient()) {
            history.saturatedUntil = now.plus(properties.getWindow());
            return new FailureObservation(now, properties.getMaxAttemptsPerClient(), true, true);
        }

        history.attempts.addLast(new FailedAttempt(now, fingerprint(accountIdentifier)));
        return new FailureObservation(now, history.attempts.size(), true, false);
    }

    public synchronized void recordSuccess(String clientIp, String accountIdentifier) {
        ClientHistory history = histories.get(clientIp);
        if (history == null) {
            return;
        }

        Instant now = clock.instant();
        prune(history, now);
        if (history.isSaturatedAt(now)) {
            return;
        }

        byte[] successfulAccount = fingerprint(accountIdentifier);
        history.attempts.removeIf(attempt -> MessageDigest.isEqual(
                attempt.accountFingerprint(), successfulAccount));
        if (history.attempts.isEmpty()) {
            histories.remove(clientIp);
        }
    }

    private void removeExpiredHistories(Instant now) {
        Iterator<Map.Entry<String, ClientHistory>> iterator = histories.entrySet().iterator();
        while (iterator.hasNext()) {
            ClientHistory history = iterator.next().getValue();
            prune(history, now);
            if (history.attempts.isEmpty() && !history.isSaturatedAt(now)) {
                iterator.remove();
            }
        }
    }

    private void prune(ClientHistory history, Instant now) {
        Instant cutoff = now.minus(properties.getWindow());
        while (!history.attempts.isEmpty()
                && history.attempts.peekFirst().occurredAt().isBefore(cutoff)) {
            history.attempts.removeFirst();
        }
        if (history.saturatedUntil != null && now.isAfter(history.saturatedUntil)) {
            history.saturatedUntil = null;
        }
    }

    private byte[] fingerprint(String accountIdentifier) {
        String normalizedIdentifier = accountIdentifier.toLowerCase(Locale.ROOT);
        String boundedIdentifier = normalizedIdentifier.length() <= MAX_ACCOUNT_IDENTIFIER_CHARACTERS
                ? normalizedIdentifier
                : normalizedIdentifier.substring(0, MAX_ACCOUNT_IDENTIFIER_CHARACTERS)
                        + "#length=" + normalizedIdentifier.length();
        try {
            Mac mac = Mac.getInstance(HMAC_ALGORITHM);
            mac.init(new SecretKeySpec(fingerprintKey, HMAC_ALGORITHM));
            return mac.doFinal(boundedIdentifier.getBytes(StandardCharsets.UTF_8));
        } catch (GeneralSecurityException unavailableAlgorithm) {
            throw new IllegalStateException("Unable to create account fingerprint", unavailableAlgorithm);
        }
    }

    private static byte[] createFingerprintKey() {
        byte[] key = new byte[HMAC_KEY_BYTES];
        new SecureRandom().nextBytes(key);
        return key;
    }

    public record FailureObservation(
            Instant occurredAt,
            int observedCount,
            boolean tracked,
            boolean saturated
    ) {
        private static FailureObservation notTracked(Instant occurredAt) {
            return new FailureObservation(occurredAt, 0, false, false);
        }
    }

    private record FailedAttempt(Instant occurredAt, byte[] accountFingerprint) {
    }

    private static final class ClientHistory {

        private final ArrayDeque<FailedAttempt> attempts = new ArrayDeque<>();
        private Instant saturatedUntil;

        private boolean isSaturatedAt(Instant timestamp) {
            return saturatedUntil != null && !timestamp.isAfter(saturatedUntil);
        }
    }
}
