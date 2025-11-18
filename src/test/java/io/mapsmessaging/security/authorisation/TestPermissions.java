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

import lombok.Getter;

@Getter
public enum TestPermissions implements Permission {

  READ("Read", "Allows Read access to the resource", 0),
  WRITE("Write", "Allows Write access to the resource", 1),
  DELETE("Delete", "Allows Delete access to the resource", 2),
  CREATE("Create", "Allows Create access to the resource", 3),;

  private final String name;
  private final String description;
  private final long mask;

  TestPermissions(final String name, final String description, final long mask) {
    this.name = name;
    this.description = description;
    this.mask = 1L <<mask;
  }
}
