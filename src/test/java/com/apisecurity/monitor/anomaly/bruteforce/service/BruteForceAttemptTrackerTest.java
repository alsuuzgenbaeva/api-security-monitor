package com.apisecurity.monitor.anomaly.bruteforce.service;

import com.apisecurity.monitor.anomaly.bruteforce.config.BruteForceDetectionProperties;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import static org.assertj.core.api.Assertions.assertThat;

class BruteForceAttemptTrackerTest {

    private static final Instant START = Instant.parse("2026-11-27T08:00:00Z");
    private static final byte[] TEST_KEY = new byte[32];

    private BruteForceDetectionProperties properties;
    private MutableClock clock;
    private BruteForceAttemptTracker tracker;

    @BeforeEach
    void setUp() {
        properties = new BruteForceDetectionProperties();
        clock = new MutableClock(START);
        tracker = new BruteForceAttemptTracker(properties, clock, TEST_KEY);
    }

    @Test
    void countsFailuresAcrossAccountsForOneClient() {
        assertThat(tracker.recordFailure("192.0.2.1", "admin").observedCount()).isEqualTo(1);
        assertThat(tracker.recordFailure("192.0.2.1", "other-user").observedCount()).isEqualTo(2);
        assertThat(tracker.recordFailure("192.0.2.2", "admin").observedCount()).isEqualTo(1);
    }

    @Test
    void rollingWindowIncludesTheBoundaryAndExpiresOlderAttempts() {
        tracker.recordFailure("192.0.2.1", "admin");

        clock.advance(Duration.ofSeconds(60));
        assertThat(tracker.recordFailure("192.0.2.1", "admin").observedCount()).isEqualTo(2);

        clock.advance(Duration.ofNanos(1));
        assertThat(tracker.recordFailure("192.0.2.1", "admin").observedCount()).isEqualTo(2);
    }

    @Test
    void successClearsOnlyTheMatchingAccountForTheSameClient() {
        tracker.recordFailure("192.0.2.1", "admin");
        tracker.recordFailure("192.0.2.1", "other-user");
        tracker.recordFailure("192.0.2.2", "admin");

        tracker.recordSuccess("192.0.2.1", "admin");

        assertThat(tracker.recordFailure("192.0.2.1", "new-user").observedCount()).isEqualTo(2);
        assertThat(tracker.recordFailure("192.0.2.2", "admin").observedCount()).isEqualTo(2);
    }

    @Test
    void accountMatchingUsesProviderCaseInsensitiveSemantics() {
        tracker.recordFailure("192.0.2.1", "Admin");

        tracker.recordSuccess("192.0.2.1", "admin");

        assertThat(tracker.recordFailure("192.0.2.1", "other").observedCount()).isEqualTo(1);
    }

    @Test
    void capacityExhaustionSkipsNewClientsUntilAnEntryExpires() {
        properties.setMaxTrackedClients(2);
        tracker.recordFailure("192.0.2.1", "admin");
        tracker.recordFailure("192.0.2.2", "admin");

        assertThat(tracker.recordFailure("192.0.2.3", "admin").tracked()).isFalse();

        clock.advance(Duration.ofSeconds(61));
        assertThat(tracker.recordFailure("192.0.2.3", "admin").tracked()).isTrue();
    }

    @Test
    void saturatedHistoryDefersAccountClearingWithoutGrowingTheCount() {
        properties.setThreshold(2);
        properties.setMaxAttemptsPerClient(3);
        tracker.recordFailure("192.0.2.1", "admin");
        tracker.recordFailure("192.0.2.1", "other-1");
        tracker.recordFailure("192.0.2.1", "other-2");

        BruteForceAttemptTracker.FailureObservation saturated =
                tracker.recordFailure("192.0.2.1", "unrecorded-account");
        tracker.recordSuccess("192.0.2.1", "admin");

        assertThat(saturated.saturated()).isTrue();
        assertThat(saturated.observedCount()).isEqualTo(3);
        assertThat(tracker.recordFailure("192.0.2.1", "next").observedCount()).isEqualTo(3);
    }

    @Test
    void concurrentUpdatesRemainConsistentAndBounded() throws Exception {
        properties.setThreshold(2);
        properties.setMaxAttemptsPerClient(50);
        int taskCount = 40;
        ExecutorService executor = Executors.newFixedThreadPool(8);
        CountDownLatch start = new CountDownLatch(1);
        List<Future<BruteForceAttemptTracker.FailureObservation>> futures = new ArrayList<>();
        try {
            for (int index = 0; index < taskCount; index++) {
                int account = index;
                futures.add(executor.submit(() -> {
                    start.await();
                    return tracker.recordFailure("192.0.2.1", "account-" + account);
                }));
            }
            start.countDown();

            List<Integer> counts = new ArrayList<>();
            for (Future<BruteForceAttemptTracker.FailureObservation> future : futures) {
                counts.add(future.get().observedCount());
            }
            assertThat(counts).containsExactlyInAnyOrderElementsOf(
                    java.util.stream.IntStream.rangeClosed(1, taskCount).boxed().toList());
        } finally {
            executor.shutdownNow();
        }
    }

    private static final class MutableClock extends Clock {

        private Instant instant;

        private MutableClock(Instant instant) {
            this.instant = instant;
        }

        private void advance(Duration duration) {
            instant = instant.plus(duration);
        }

        @Override
        public ZoneId getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(ZoneId zone) {
            return this;
        }

        @Override
        public Instant instant() {
            return instant;
        }
    }
}
