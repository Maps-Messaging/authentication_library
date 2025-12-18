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

package io.mapsmessaging.security.authorisation;

import io.mapsmessaging.security.access.Group;
import io.mapsmessaging.security.access.Identity;
import java.util.List;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class AccessDecision {

  private Identity identity;

  private Permission permission;

  private ProtectedResource protectedResource;

  private boolean allowed;

  private DecisionReason decisionReason;

  /**
   * Grants that directly contributed to this decision
   * (for example explicit allow or deny entries).
   */
  @Builder.Default
  private List<Grant> contributingGrants = List.of();

  /**
   * Groups that contributed to this decision, if any.
   */
  @Builder.Default
  private List<Group> contributingGroups = List.of();

  /**
   * Optional human readable detail intended for logs or UI.
   * Do not parse this in code, use the structured fields instead.
   */
  private String detailMessage;

}
