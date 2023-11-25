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

package io.mapsmessaging.security.identity.impl.base;

import io.mapsmessaging.logging.Logger;
import io.mapsmessaging.logging.LoggerFactory;
import io.mapsmessaging.security.access.mapping.UserIdMap;
import io.mapsmessaging.security.access.mapping.UserMapManagement;
import io.mapsmessaging.security.identity.IdentityEntry;
import io.mapsmessaging.security.identity.NoSuchUserFoundException;
import io.mapsmessaging.security.identity.impl.apache.HtPasswdEntry;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static io.mapsmessaging.security.logging.AuthLogMessages.NO_SUCH_USER_FOUND;

public abstract class FileBaseIdentities extends FileLoader {

  private final Logger logger = LoggerFactory.getLogger(FileBaseIdentities.class);
  private final Map<String, IdentityEntry> usernamePasswordMap;

  protected FileBaseIdentities(String filepath) {
    super(filepath);
    usernamePasswordMap = new LinkedHashMap<>();
  }

  public abstract String getDomain();

  public IdentityEntry findEntry(String username) {
    return usernamePasswordMap.get(username);
  }

  public char[] getPasswordHash(String username) throws NoSuchUserFoundException {
    IdentityEntry identityEntry = usernamePasswordMap.get(username);
    if (identityEntry == null) {
      logger.log(NO_SUCH_USER_FOUND, username);
      throw new NoSuchUserFoundException("User: " + username + " not found");
    }
    return identityEntry.getPassword().toCharArray();
  }

  public List<IdentityEntry> getEntries() {
    return (List<IdentityEntry>) usernamePasswordMap.values();
  }

  protected abstract IdentityEntry load(String line);

  public void parse(String line) {
    IdentityEntry identityEntry = load(line);
    usernamePasswordMap.put(identityEntry.getUsername(), identityEntry);
    if (UserMapManagement.getGlobalInstance().get(getDomain() + ":" + identityEntry.getUsername())
        == null) {
      UserMapManagement.getGlobalInstance()
          .add(new UserIdMap(UUID.randomUUID(), identityEntry.getUsername(), getDomain(), ""));
    }
  }

  public void addEntry(String username, String passwordHash) {
    IdentityEntry identityEntry = new HtPasswdEntry(username, passwordHash);
    usernamePasswordMap.put(username, identityEntry);
    if (UserMapManagement.getGlobalInstance().get(getDomain() + ":" + identityEntry.getUsername())
        == null) {
      UserMapManagement.getGlobalInstance()
          .add(new UserIdMap(UUID.randomUUID(), identityEntry.getUsername(), getDomain(), ""));
    }
  }
}
