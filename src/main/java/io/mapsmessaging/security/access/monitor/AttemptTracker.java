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

import java.time.Clock;
import java.time.Instant;
import java.util.Iterator;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

public class AttemptTracker {

  private final ConcurrentMap<String, AuthState> stateMap;
  private final Clock clock;
  private final int failureDecaySeconds;

  public AttemptTracker(Clock clock, int failureDecaySeconds) {
    this.stateMap = new ConcurrentHashMap<>();
    this.clock = clock;
    this.failureDecaySeconds = failureDecaySeconds;
  }

  public AuthState getState(String username) {
    Instant now = clock.instant();

    return stateMap.compute(username, (key, state) -> {
      if (state == null) {
        return new AuthState();
      }
      if (state.shouldDecayFailures(now, failureDecaySeconds)) {
        return new AuthState(); // evict
      }
      return state;
    });
  }

  public AuthState peekState(String username) {
    return stateMap.get(username);
  }

  public ConcurrentMap<String, AuthState> snapshot() {
    return new ConcurrentHashMap<>(stateMap);
  }

  public void clearState(String username) {
    stateMap.remove(username);
  }

  public int sweep(Instant cutoff) {
    int removed = 0;
    Instant now = clock.instant();

    for (Iterator<Map.Entry<String, AuthState>> iterator = stateMap.entrySet().iterator(); iterator.hasNext(); ) {
      var entry = iterator.next();
      String username = entry.getKey();
      AuthState state = entry.getValue();

      if (state == null || state.isLocked(now)) {
        continue;
      }

      Instant lastFailure = state.getLastFailureAt();
      Instant lastSuccess = state.getLastSuccessAt();
      Instant lastActivity = lastFailure != null ? lastFailure : lastSuccess;
      if (lastActivity == null || (lastActivity.isBefore(cutoff) && stateMap.remove(username, state))) {
        removed++;
      }
    }
    return removed;
  }

  public int size() {
    return stateMap.size();
  }
}
