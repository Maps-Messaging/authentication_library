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

import java.time.Instant;
import lombok.Getter;

@Getter
public class AuthState {

  private int failureCount;
  private Instant firstFailureAt;
  private Instant lastFailureAt;
  private Instant lockedUntil;
  private Instant lastSuccessAt;
  private int lockCount;

  public AuthState() {
    reset();
  }

  public void recordFailure(Instant now) {
    if (failureCount == 0) {
      firstFailureAt = now;
    }
    failureCount++;
    lastFailureAt = now;
  }

  public void incrementLockCount() {
    lockCount++;
  }

  public void resetLockCount() {
    lockCount = 0;
  }

  public void recordSuccess(Instant now) {
    lastSuccessAt = now;
    resetFailures();
  }

  public boolean isLocked(Instant now) {
    return lockedUntil != null && lockedUntil.isAfter(now);
  }

  public long getRemainingLockSeconds(Instant now) {
    if (lockedUntil == null || !lockedUntil.isAfter(now)) {
      return 0;
    }
    return lockedUntil.getEpochSecond() - now.getEpochSecond();
  }

  public void lockUntil(Instant until) {
    lockedUntil = until;
  }

  public boolean shouldDecayFailures(Instant now, int decaySeconds) {
    if (decaySeconds <= 0 || lastFailureAt == null) {
      return false;
    }
    return now.getEpochSecond() - lastFailureAt.getEpochSecond() > decaySeconds;
  }

  public void resetFailures() {
    failureCount = 0;
    firstFailureAt = null;
    lastFailureAt = null;
    lockedUntil = null;
  }

  public void reset() {
    failureCount = 0;
    firstFailureAt = null;
    lastFailureAt = null;
    lockedUntil = null;
    lastSuccessAt = null;
  }
}
