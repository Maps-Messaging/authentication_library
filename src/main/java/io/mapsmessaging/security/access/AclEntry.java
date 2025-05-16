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

package io.mapsmessaging.security.access;

import io.mapsmessaging.security.access.expiry.AccessEntryExpiryPolicy;
import io.mapsmessaging.security.access.expiry.NoExpiryPolicy;
import java.util.UUID;
import lombok.Getter;

@Getter
public class AclEntry {

  private final UUID authId;
  private final long permissions;
  private final AccessEntryExpiryPolicy expiryPolicy;

  public AclEntry(UUID authId, long permissions) {
    this(authId, permissions, new NoExpiryPolicy());
  }

  public AclEntry(UUID authId, long permissions, AccessEntryExpiryPolicy expiryPolicy) {
    this.authId = authId;
    this.permissions = permissions;
    this.expiryPolicy = expiryPolicy;
  }

  public boolean matches(UUID authId) {
    return this.authId.equals(authId);
  }

}