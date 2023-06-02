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

import static io.mapsmessaging.security.logging.AuthLogMessages.NO_SUCH_USER_FOUND;

import io.mapsmessaging.logging.Logger;
import io.mapsmessaging.logging.LoggerFactory;
import io.mapsmessaging.security.identity.IdentityEntry;
import io.mapsmessaging.security.identity.NoSuchUserFoundException;
import java.util.LinkedHashMap;
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

  public char[] getPasswordHash(String username) throws NoSuchUserFoundException {
    IdentityEntry identityEntry = usernamePasswordMap.get(username);
    if (identityEntry == null) {
      logger.log(NO_SUCH_USER_FOUND, username);
      throw new NoSuchUserFoundException("User: " + username + " not found");
    }
    return identityEntry.getPassword().toCharArray();
  }

  protected abstract IdentityEntry load(String line);

  public void parse(String line) {
    IdentityEntry identityEntry = load(line);
    usernamePasswordMap.put(identityEntry.getUsername(), identityEntry);
  }
}
