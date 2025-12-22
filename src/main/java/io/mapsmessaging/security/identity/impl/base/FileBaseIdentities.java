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

package io.mapsmessaging.security.identity.impl.base;

import io.mapsmessaging.logging.Logger;
import io.mapsmessaging.logging.LoggerFactory;
import io.mapsmessaging.security.identity.IdentityEntry;
import io.mapsmessaging.security.identity.NoSuchUserFoundException;
import io.mapsmessaging.security.passwords.PasswordBuffer;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public abstract class FileBaseIdentities extends FileLoader {

  private final Logger logger = LoggerFactory.getLogger(FileBaseIdentities.class);
  private final Map<String, IdentityEntry> usernamePasswordMap;

  protected FileBaseIdentities(String filepath) {
    super(filepath);
    usernamePasswordMap = new LinkedHashMap<>();
  }

  public IdentityEntry findEntry(String username) {
    return usernamePasswordMap.get(username);
  }

  public PasswordBuffer getPasswordHash(String username) throws IOException, GeneralSecurityException {
    IdentityEntry identityEntry = usernamePasswordMap.get(username);
    if (identityEntry == null) {
      throw new NoSuchUserFoundException("User: " + username + " not found");
    }
    return identityEntry.getPassword();
  }

  public List<IdentityEntry> getEntries() {
    return new ArrayList<>(usernamePasswordMap.values());
  }

  protected abstract IdentityEntry load(String line);

  protected abstract IdentityEntry create(String username, char[] hash);

  public void parse(String line) {
    IdentityEntry identityEntry = load(line);
    usernamePasswordMap.put(identityEntry.getUsername(), identityEntry);
  }

  public void addEntry(String username, char[] passwordHash) throws IOException {
    IdentityEntry identityEntry = create(username, passwordHash);
    usernamePasswordMap.put(username, identityEntry);
    add(identityEntry.toString());
  }

  public void deleteEntry(String username) throws IOException {
    IdentityEntry entry = usernamePasswordMap.get(username);
    if (entry != null) {
      usernamePasswordMap.remove(username);
      delete(username);
    }
  }
}
