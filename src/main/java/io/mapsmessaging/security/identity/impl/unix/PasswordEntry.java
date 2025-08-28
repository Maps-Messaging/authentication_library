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

package io.mapsmessaging.security.identity.impl.unix;

import lombok.Getter;

@Getter
public class PasswordEntry {

  private final String username;
  private final String description;
  private final String homeDirectory;
  private final int id;
  private final int groupId;

  public PasswordEntry(String line) {
    String[] entries = line.split(":");
    username = entries[0];
    groupId = Integer.parseInt(entries[2]);
    id = Integer.parseInt(entries[3]);
    description = entries[4];
    homeDirectory = entries[5];
  }
}
