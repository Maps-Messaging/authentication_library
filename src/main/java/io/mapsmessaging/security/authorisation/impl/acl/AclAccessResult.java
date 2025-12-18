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
package io.mapsmessaging.security.authorisation.impl.acl;

import io.mapsmessaging.security.authorisation.Access;
import java.util.UUID;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class AclAccessResult {

  /**
   * Final decision for the requested access.
   */
  private Access access;

  /**
   * The UUID (identity or group) that contributed the deciding ACL entry.
   * May be null if {@link #access} is {@link Access#UNKNOWN}.
   */
  private UUID decidingAuthId;

  /**
   * True if the decidingAuthId represents a group, false if it is an identity.
   */
  private boolean groupDecision;

  /**
   * The ACL entry that actually decided the outcome, or null if UNKNOWN.
   */
  private AclEntry aclEntry;

}
