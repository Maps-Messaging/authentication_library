/*
 * Copyright [ 2020 - 2023 ] [Matthew Buckton]
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package io.mapsmessaging.security.identity.impl.unix;

import lombok.Getter;

public class PasswordEntry implements Comparable<PasswordEntry>{

  @Getter
  private final String username;
  @Getter
  private final String description;
  @Getter
  private final String homeDirectory;
  @Getter
  private final int id;
  @Getter
  private final int groupId;

  public PasswordEntry(String line) {
    String[] entries = line.split(":");
    username = entries[0];
    groupId = Integer.parseInt(entries[2]);
    id = Integer.parseInt(entries[3]);
    description = entries[4];
    homeDirectory = entries[5];
  }

  @Override
  public int compareTo(PasswordEntry o) {
    return username.compareTo(o.username);
  }

}
