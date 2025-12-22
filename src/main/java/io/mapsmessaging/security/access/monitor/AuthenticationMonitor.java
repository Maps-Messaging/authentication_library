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

import io.mapsmessaging.logging.Logger;
import io.mapsmessaging.logging.LoggerFactory;
import io.mapsmessaging.security.logging.AuthLogMessages;
import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

public class AuthenticationMonitor {

  private final AuthenticationMonitorConfig config;
  private final AttemptTracker tracker;
  private final Clock clock;
  private final Logger logger = LoggerFactory.getLogger(AuthenticationMonitor.class);

  public AuthenticationMonitor(AuthenticationMonitorConfig config) {
    this(config, Clock.systemUTC());
  }

  public AuthenticationMonitor(AuthenticationMonitorConfig config, Clock clock) {
    this.clock = clock;
    this.config = config;
    this.tracker = new AttemptTracker(clock, config.getFailureDecaySeconds());
  }

  public boolean isLocked(String username) {
    AuthState state = tracker.peekState(username);
    if (state == null) {
      return false;
    }
    return state.isLocked(clock.instant());
  }

  public List<LockStatus> getLockedUsers() {
    Instant now = clock.instant();
    List<LockStatus> result = new ArrayList<>();
    for (Map.Entry<String, AuthState> entry : tracker.snapshot().entrySet()) {
      AuthState state = entry.getValue();
      if (state.isLocked(now)) {
        result.add(
            new LockStatus(
                entry.getKey(),
                true,
                state.getRemainingLockSeconds(now),
                state.getLockedUntil().toString()));
      }
    }

    return result;
  }

  public int sweepOldEntries(int idleSeconds) {
    if (idleSeconds <= 0) {
      return 0;
    }
    Instant cutoff = clock.instant().minusSeconds(idleSeconds);
    return tracker.sweep(cutoff);
  }

  int getTrackedUserCount() {
    return tracker.size();
  }

  public LockStatus getLockStatus(String username) {
    AuthState state = tracker.getState(username);
    Instant now = clock.instant();

    boolean locked = state.isLocked(now);
    long remaining = state.getRemainingLockSeconds(now);

    String lockedUntilIso =
        state.getLockedUntil() == null ? null : state.getLockedUntil().toString();

    return new LockStatus(username, locked, remaining, lockedUntilIso);
  }

  public void recordFailure(String username, String ipAddress) {
    Instant now = clock.instant();
    AuthState state = tracker.getState(username);

    if (state.isLocked(now)) {
      // already locked, no extra logging
      return;
    }

    state.recordFailure(now);

    logger.log(AuthLogMessages.AUTH_FAILURE, username, state.getFailureCount(), ipAddress);

    if (state.getFailureCount() >= config.getMaxFailuresBeforeLock()) {
      long lockSeconds = computeLockSeconds(state);
      state.lockUntil(now.plusSeconds(lockSeconds));
      state.incrementLockCount();

      logger.log(
          AuthLogMessages.AUTH_LOCKOUT_STARTED,
          username,
          state.getFailureCount(),
          lockSeconds,
          ipAddress);
    }
  }

  public void recordSuccess(String username, String ipAddress) {
    AuthState state = tracker.getState(username);

    if (state.getFailureCount() > 0) {
      logger.log(
          AuthLogMessages.AUTH_SUCCESS_AFTER_FAILURES,
          username,
          state.getFailureCount(),
          ipAddress);
    }

    state.recordSuccess(clock.instant());
    state.resetLockCount();
    tracker.clearState(username);
  }

  private long computeLockSeconds(AuthState state) {
    long base = config.getInitialLockSeconds();
    long lock = base << state.getLockCount();
    return Math.min(lock, config.getMaxLockSeconds());
  }

  public void reset(String username) {
    tracker.clearState(username);
  }
}
