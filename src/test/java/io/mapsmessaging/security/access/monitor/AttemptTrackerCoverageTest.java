/*
 * Copyright [ 2024 - 2026 ] MapsMessaging B.V.
 */
package io.mapsmessaging.security.access.monitor;

import static org.junit.jupiter.api.Assertions.*;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import org.junit.jupiter.api.Test;

class AttemptTrackerCoverageTest {

  @Test
  void tracksCreatesUpdatesSnapshotsAndClearsState() {
    Instant now = Instant.parse("2026-09-29T00:00:00Z");
    AttemptTracker tracker = new AttemptTracker(Clock.fixed(now, ZoneOffset.UTC), 60);

    AuthState state = tracker.getState("alice");
    assertNotNull(state);
    assertEquals(1, tracker.size());
    assertSame(state, tracker.peekState("alice"));

    AuthState updated = tracker.updateState("alice", (username, current) -> {
      current.recordFailure(now.minusSeconds(10));
      return current;
    });
    assertSame(state, updated);
    assertEquals(1, updated.getFailureCount());
    assertEquals(1, tracker.snapshot().size());
    assertSame(updated, tracker.findState("alice"));

    tracker.clearState("alice");
    assertNull(tracker.peekState("alice"));
    assertEquals(0, tracker.size());
  }

  @Test
  void decaysFailuresWhenReadingState() {
    Instant now = Instant.parse("2026-09-29T00:00:00Z");
    AttemptTracker tracker = new AttemptTracker(Clock.fixed(now, ZoneOffset.UTC), 30);

    tracker.updateState("alice", (username, state) -> {
      AuthState value = state == null ? new AuthState() : state;
      value.recordFailure(now.minusSeconds(31));
      return value;
    });

    assertNull(tracker.findState("alice"));
    assertEquals(0, tracker.size());

    AuthState reset = tracker.updateState("bob", (username, state) -> {
      AuthState value = new AuthState();
      value.recordFailure(now.minusSeconds(31));
      return value;
    });
    assertEquals(1, reset.getFailureCount());

    AuthState refreshed = tracker.getState("bob");
    assertNotSame(reset, refreshed);
    assertEquals(0, refreshed.getFailureCount());
  }

  @Test
  void sweepRemovesExpiredUnlockedStatesButKeepsLockedOnes() {
    Instant now = Instant.parse("2026-09-29T00:00:00Z");
    AttemptTracker tracker = new AttemptTracker(Clock.fixed(now, ZoneOffset.UTC), 0);

    tracker.updateState("old", (username, state) -> {
      AuthState value = new AuthState();
      value.recordFailure(now.minusSeconds(120));
      return value;
    });
    tracker.updateState("recent", (username, state) -> {
      AuthState value = new AuthState();
      value.recordSuccess(now.minusSeconds(5));
      return value;
    });
    tracker.updateState("locked", (username, state) -> {
      AuthState value = new AuthState();
      value.recordFailure(now.minusSeconds(120));
      value.lockUntil(now.plusSeconds(60));
      return value;
    });
    tracker.updateState("empty", (username, state) -> new AuthState());

    assertEquals(2, tracker.sweep(now.minusSeconds(30)));
    assertNull(tracker.peekState("old"));
    assertNull(tracker.peekState("empty"));
    assertNotNull(tracker.peekState("recent"));
    assertNotNull(tracker.peekState("locked"));
  }

  @Test
  void authStateCoversLockDecayAndResetSemantics() {
    Instant now = Instant.parse("2026-09-29T00:00:00Z");
    AuthState state = new AuthState();

    assertFalse(state.isLocked(now));
    assertEquals(0, state.getRemainingLockSeconds(now));
    assertFalse(state.shouldDecayFailures(now, 30));

    state.recordFailure(now.minusSeconds(40));
    state.recordFailure(now.minusSeconds(20));
    assertEquals(2, state.getFailureCount());
    assertNotNull(state.getFirstFailureAt());
    assertTrue(state.shouldDecayFailures(now.plusSeconds(20), 30));

    state.incrementLockCount();
    state.incrementLockCount();
    assertEquals(2, state.getLockCount());
    state.resetLockCount();
    assertEquals(0, state.getLockCount());

    state.lockUntil(now.plusSeconds(45));
    assertTrue(state.isLocked(now));
    assertEquals(45, state.getRemainingLockSeconds(now));

    state.recordSuccess(now);
    assertEquals(now, state.getLastSuccessAt());
    assertEquals(0, state.getFailureCount());
    assertNull(state.getLockedUntil());

    state.recordFailure(now);
    state.reset();
    assertEquals(0, state.getFailureCount());
    assertNull(state.getLastFailureAt());
    assertNull(state.getLastSuccessAt());
  }
}
