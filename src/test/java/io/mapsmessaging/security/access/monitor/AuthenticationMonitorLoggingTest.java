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

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.spi.ILoggingEvent;
import io.mapsmessaging.security.InMemoryAppender;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class AuthenticationMonitorLoggingTest {

  private static final String IP = "203.0.113.10";

  private MutableClock clock;
  private AuthenticationMonitorConfig config;
  private AuthenticationMonitor monitor;

  @BeforeEach
  void setUp() {
    InMemoryAppender.clearLogEvents();

    clock = new MutableClock(Instant.parse("2025-01-01T00:00:00Z"));

    config = new AuthenticationMonitorConfig();
    config.setEnableSoftDelay(false);
    config.setSoftDelayMillisPerFailure(0);
    config.setMaxSoftDelayMillis(0);

    config.setFailureDecaySeconds(60);
    config.setMaxFailuresBeforeLock(3);

    // Keep locked long enough so sweep tests are meaningful
    config.setInitialLockSeconds(600);
    config.setMaxLockSeconds(600);

    monitor = new AuthenticationMonitor(config, clock);
  }

  @Test
  void locksAtThresholdAndUnlocksAfterDuration() {
    String username = "userB";

    monitor.recordFailure(username, IP);
    monitor.recordFailure(username, IP);
    assertFalse(monitor.isLocked(username));

    monitor.recordFailure(username, IP);
    assertTrue(monitor.isLocked(username));

    clock.advanceSeconds(601);
    assertFalse(monitor.isLocked(username));
  }

  @Test
  void sweepRemovesIdleUnlockedEntriesButKeepsLockedOnes() {
    String userA = "userA";
    String userB = "userB";

    monitor.recordFailure(userA, IP); // not locked
    monitor.recordFailure(userB, IP);
    monitor.recordFailure(userB, IP);
    monitor.recordFailure(userB, IP); // locked

    assertFalse(monitor.isLocked(userA));
    assertTrue(monitor.isLocked(userB));

    // Make userA idle > 5 min, keep userB still locked (lock = 10 min)
    clock.advanceSeconds(360);

    int removed = monitor.sweepOldEntries(300);
    assertEquals(1, removed);

    assertTrue(monitor.isLocked(userB));
    assertTrue(monitor.getLockedUsers().stream().anyMatch(s -> s.username().equals(userB) && s.locked()));
  }

  @Test
  void sweepRemovesNothingWhenNoEntriesEligible() {
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
  void logsAuthFailureContainsUsernameAndIp() {
    String username = "user1";

    monitor.recordFailure(username, IP);

    List<ILoggingEvent> events = findEventsContaining("AUTH_FAILURE");
    assertEquals(1, events.size());

    ILoggingEvent event = events.get(0);
    assertNotNull(event.getFormattedMessage());
    assertTrue(event.getFormattedMessage().contains(username));
    assertTrue(event.getFormattedMessage().contains(IP));
  }

  @Test
  void logsLockoutStartedContainsUsernameAndIp() {
    String username = "user1";

    monitor.recordFailure(username, IP);
    monitor.recordFailure(username, IP);
    monitor.recordFailure(username, IP);
    monitor.recordFailure(username, IP); // lock

    List<ILoggingEvent> events = findEventsContaining("AUTH_LOCKOUT");
    assertEquals(1, events.size());

    ILoggingEvent event = events.get(0);
    assertNotNull(event.getFormattedMessage());
    assertTrue(event.getFormattedMessage().contains(username));
    assertTrue(event.getFormattedMessage().contains(IP));
  }

  @Test
  void doesNotSpamFailureOrLockoutLogsWhileAlreadyLocked() {
    String username = "user1";

    monitor.recordFailure(username, IP);
    monitor.recordFailure(username, IP);
    monitor.recordFailure(username, IP); // locked

    int failuresBefore = findEventsContaining("AUTH_FAILURE").size();
    int lockoutsBefore = findEventsContaining("AUTH_LOCKOUT_STARTED").size();

    clock.advanceSeconds(10); // still locked
    monitor.recordFailure(username, IP);
    monitor.recordFailure(username, IP);

    int failuresAfter = findEventsContaining("AUTH_FAILURE").size();
    int lockoutsAfter = findEventsContaining("AUTH_LOCKOUT_STARTED").size();

    assertEquals(failuresBefore, failuresAfter);
    assertEquals(lockoutsBefore, lockoutsAfter);
  }

  @Test
  void lockoutLogIsAtLeastWarnOrInfo() {
    String username = "user1";

    monitor.recordFailure(username, IP);
    monitor.recordFailure(username, IP);
    monitor.recordFailure(username, IP); // lock

    List<ILoggingEvent> events = findEventsContaining("AUTH_LOCKOUT");
    assertEquals(1, events.size());

    Level level = events.get(0).getLevel();
    assertTrue(level.isGreaterOrEqual(Level.INFO));
  }

  private List<ILoggingEvent> findEventsContaining(String token) {
    return InMemoryAppender.logEvents.stream()
        .filter(e -> e != null)
        .filter(e -> e.getFormattedMessage() != null)
        .filter(e -> e.getFormattedMessage().contains(token))
        .toList();
  }

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
