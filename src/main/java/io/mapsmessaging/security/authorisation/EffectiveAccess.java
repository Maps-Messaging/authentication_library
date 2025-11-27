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

import io.mapsmessaging.security.access.Identity;
import java.util.Map;
import java.util.Set;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class EffectiveAccess {

  private Identity identity;

  private ProtectedResource protectedResource;

  @Builder.Default
  private Set<Permission> allowedPermissions = Set.of();

  @Builder.Default
  private Set<Permission> deniedPermissions =  Set.of();

  /**
   * Optional per-permission decisions for detailed inspection.
   * Implementations may choose not to populate this to save work.
   */
  @Builder.Default
  private Map<Permission, AccessDecision> decisionsByPermission = Map.of();

}
