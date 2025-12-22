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

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class AuthenticationMonitorConfig {

  /** Number of consecutive failures before a lockout is applied. */
  private int maxFailuresBeforeLock = 5;

  /** Initial lockout duration in seconds. */
  private int initialLockSeconds = 30;

  /** Maximum lockout duration in seconds. */
  private int maxLockSeconds = 900;

  /** Time window after which failures are forgotten. If zero or negative, failures never decay. */
  private int failureDecaySeconds = 900;

  /** Enable soft delay before failure response. */
  private boolean enableSoftDelay = true;

  /** Delay added per failure in milliseconds. */
  private int softDelayMillisPerFailure = 200;

  /** Maximum soft delay in milliseconds. */
  private int maxSoftDelayMillis = 2000;
}
