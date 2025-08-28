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

import io.mapsmessaging.security.identity.impl.base.FileLoader;
import java.util.LinkedHashMap;
import java.util.Map;

public class PasswordFileManager extends FileLoader {

  private final Map<String, PasswordEntry> users;

  public PasswordFileManager(String filename) {
    super(filename);
    users = new LinkedHashMap<>();
    load();
  }

  protected PasswordEntry load(String line)  {
    return new PasswordEntry(line);
  }

  public void parse(String line)  {
    PasswordEntry user = load(line);
    users.put(user.getUsername(), user);
  }

  public PasswordEntry findUser(String name) {
    return users.get(name);
  }

}