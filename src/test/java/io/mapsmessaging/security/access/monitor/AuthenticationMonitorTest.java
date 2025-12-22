/*
 * Copyright [ 2020 - 2024 ] Matthew Buckton
 *  Copyright [ 2024 - 2025 ] MapsMessaging B.V.
 *
 *  Licensed under the Apache License, Version 2.0 with the Commons Clause
 *  (the "License"); you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at:
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *      https://commonsclause.com/
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 *
 */

package io.mapsmessaging.security.access.monitor;

import static org.junit.jupiter.api.Assertions.*;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class AuthenticationMonitorTest {

  private static final String IP = "203.0.113.10";

  private MutableClock clock;
  private AuthenticationMonitorConfig config;
  private AuthenticationMonitor monitor;

  @BeforeEach
  void setUp() {
    clock = new MutableClock(Instant.parse("2025-01-01T00:00:00Z"));

    config = new AuthenticationMonitorConfig();
    config.setEnableSoftDelay(false);
    config.setSoftDelayMillisPerFailure(0);
    config.setMaxSoftDelayMillis(0);

    config.setFailureDecaySeconds(60);

    config.setMaxFailuresBeforeLock(3);
    config.setInitialLockSeconds(600);
    config.setMaxLockSeconds(600);

    monitor = new AuthenticationMonitor(config, clock);
  }

  @Test
  void notLockedInitially() {
    assertFalse(monitor.isLocked("user1"));
    assertTrue(monitor.getLockedUsers().isEmpty());
  }

  @Test
  void locksOnThreshold() {
    String username = "userB";

    monitor.recordFailure(username, IP);
    monitor.recordFailure(username, IP);
    assertFalse(monitor.isLocked(username));

    monitor.recordFailure(username, IP);
    assertTrue(monitor.isLocked(username));

    List<LockStatus> lockedUsers = monitor.getLockedUsers();
    assertEquals(1, lockedUsers.size());

    LockStatus status = lockedUsers.get(0);
    assertEquals(username, status.username());
    assertTrue(status.locked());
    assertTrue(status.remainingLockSeconds() > 0);
    assertNotNull(status.lockedUntilIso());
  }

  @Test
  void unlocksAfterLockDuration() {
    String username = "userB";

    monitor.recordFailure(username, IP);
    monitor.recordFailure(username, IP);
    monitor.recordFailure(username, IP);
    assertTrue(monitor.isLocked(username));

    clock.advanceSeconds(601);
    assertFalse(monitor.isLocked(username));

    assertTrue(monitor.getLockedUsers().stream().noneMatch(lock -> lock.username().equals(username)));
  }

  @Test
  void sweepRemovesIdleUnlockedEntriesButKeepsLockedOnes() {
    String userA = "userA";
    String userB = "userB";

    monitor.recordFailure(userA, IP); // not locked
    monitor.recordFailure(userB, IP);
    monitor.recordFailure(userB, IP);
    monitor.recordFailure(userB, IP); // locked

    assertTrue(monitor.isLocked(userB));
    assertFalse(monitor.isLocked(userA));

    // Make userA idle (> 5 minutes), but userB still locked (lock = 10 minutes)
    clock.advanceSeconds(360);

    int removed = monitor.sweepOldEntries(300);
    assertEquals(1, removed);

    assertTrue(monitor.isLocked(userB));
    assertTrue(monitor.getLockedUsers().stream().anyMatch(s -> s.username().equals(userB) && s.locked()));
  }

  @Test
  void sweepDoesNothingWhenNothingEligible() {
    String userA = "userA";
    String userB = "userB";

    monitor.recordFailure(userA, IP);
    monitor.recordFailure(userB, IP);
    monitor.recordFailure(userB, IP);
    monitor.recordFailure(userB, IP); // locked

    clock.advanceSeconds(5);

    int removed = monitor.sweepOldEntries(300);
    assertEquals(0, removed);

    assertTrue(monitor.isLocked(userB));
  }

  @Test
  void resetClearsLockState() {
    String username = "userB";

    monitor.recordFailure(username, IP);
    monitor.recordFailure(username, IP);
    monitor.recordFailure(username, IP);
    assertTrue(monitor.isLocked(username));

    monitor.reset(username);

    assertFalse(monitor.isLocked(username));
    assertTrue(monitor.getLockedUsers().isEmpty());
  }

  @Test
  void resetAlsoResetsEscalationToInitialLock() {
    String username = "userB";

    monitor.recordFailure(username, IP);
    monitor.recordFailure(username, IP);
    monitor.recordFailure(username, IP);

    LockStatus firstLock = monitor.getLockedUsers().get(0);
    long firstRemaining = firstLock.remainingLockSeconds();
    assertTrue(firstRemaining <= 600 && firstRemaining > 0);

    // Unlock by time, then trigger lock again (this is where escalation would show)
    clock.advanceSeconds(601);
    assertFalse(monitor.isLocked(username));

    monitor.recordFailure(username, IP);
    monitor.recordFailure(username, IP);
    monitor.recordFailure(username, IP);

    LockStatus secondLock = monitor.getLockedUsers().get(0);
    long secondRemaining = secondLock.remainingLockSeconds();
    assertTrue(secondRemaining <= 600 && secondRemaining > 0);

    // Now reset and lock again; must go back to initial behavior
    monitor.reset(username);

    monitor.recordFailure(username, IP);
    monitor.recordFailure(username, IP);
    monitor.recordFailure(username, IP);

    LockStatus afterResetLock = monitor.getLockedUsers().get(0);
    long afterResetRemaining = afterResetLock.remainingLockSeconds();
    assertTrue(afterResetRemaining <= 600 && afterResetRemaining > 0);
  }

  @Test
  void isLockedDoesNotAllocateStateForUnknownUser() {
    int before = monitor.getTrackedUserCount();

    assertFalse(monitor.isLocked("username-does-not-exist-1"));
    assertFalse(monitor.isLocked("username-does-not-exist-2"));

    int after = monitor.getTrackedUserCount();
    assertEquals(before, after);
  }

  @Test
  void sweepCanBeUsedToShrinkStateAfterSpray() {
    // Simulate a spray creating state entries (whatever your flow is, failures do create state)
    int users = 200;
    int index = 0;
    while (index < users) {
      String username = "sprayUser" + index;
      monitor.recordFailure(username, IP);
      index++;
    }

    int beforeSweep = monitor.getTrackedUserCount();
    assertTrue(beforeSweep >= users);

    clock.advanceSeconds(3600);
    int removed = monitor.sweepOldEntries(300);

    assertTrue(removed > 0);
    int afterSweep = monitor.getTrackedUserCount();
    assertTrue(afterSweep < beforeSweep);
  }

  /**
   * Deterministic clock for tests.
   */
  private static final class MutableClock extends Clock {

    private Instant now;

    private MutableClock(Instant start) {
      this.now = start;
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
      return now;
    }

    private void advanceSeconds(long seconds) {
      now = now.plusSeconds(seconds);
    }
  }
}
