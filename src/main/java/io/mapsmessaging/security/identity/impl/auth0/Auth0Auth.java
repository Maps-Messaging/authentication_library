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

package io.mapsmessaging.security.identity.impl.auth0;

import com.auth0.client.auth.AuthAPI;
import com.auth0.client.mgmt.ManagementAPI;
import io.mapsmessaging.security.identity.GroupEntry;
import io.mapsmessaging.security.identity.IdentityEntry;
import io.mapsmessaging.security.identity.IdentityLookup;
import io.mapsmessaging.security.identity.NoSuchUserFoundException;
import io.mapsmessaging.security.identity.parsers.PasswordParser;
import java.io.IOException;
import java.util.List;
import java.util.Map;

public class Auth0Auth implements IdentityLookup {

  private final String domain;
  private final String clientId;
  private final String clientSecret;
  private final String apiToken;

  private final AuthAPI authAPI;
  private final ManagementAPI mgmt;

  private long cacheTime = 30000;

  public Auth0Auth() {
    domain = "";
    clientId = "";
    clientSecret = "";
    apiToken = "";
    authAPI = null;
    mgmt = null;
  }

  public Auth0Auth(Map<String, ?> config) {
    domain = (String) config.get("domain");
    clientId = (String) config.get("clientId");
    clientSecret = (String) config.get("clientSecret");
    apiToken = (String) config.get("apiToken");
    String cacheTimeString = (String) config.get("cacheTime");
    if (cacheTimeString != null && !cacheTimeString.trim().isEmpty()) {
      cacheTime = Long.parseLong(cacheTimeString.trim());
    }
    authAPI = AuthAPI.newBuilder(domain, clientId, clientSecret).build();
    mgmt = ManagementAPI.newBuilder(domain, apiToken).build();
  }

  @Override
  public String getName() {
    return "auth0";
  }

  @Override
  public String getDomain() {
    return getName();
  }

  @Override
  public char[] getPasswordHash(String username) throws NoSuchUserFoundException {
    return new char[0];
  }

  @Override
  public IdentityEntry findEntry(String username) {
    return null;
  }

  @Override
  public List<IdentityEntry> getEntries() {
    return null;
  }

  @Override
  public GroupEntry findGroup(String groupName) {
    return null;
  }

  @Override
  public List<GroupEntry> getGroups() {
    return IdentityLookup.super.getGroups();
  }

  @Override
  public IdentityLookup create(Map<String, ?> config) {
    return null;
  }

  @Override
  public boolean createGroup(String groupName) throws IOException {
    return IdentityLookup.super.createGroup(groupName);
  }

  @Override
  public boolean deleteGroup(String groupName) throws IOException {
    return IdentityLookup.super.deleteGroup(groupName);
  }

  @Override
  public boolean createUser(String username, String passwordHash, PasswordParser passwordParser)
      throws IOException {
    return IdentityLookup.super.createUser(username, passwordHash, passwordParser);
  }

  @Override
  public boolean deleteUser(String username) throws IOException {
    return IdentityLookup.super.deleteUser(username);
  }

  @Override
  public void updateGroup(GroupEntry groupEntry) throws IOException {
    IdentityLookup.super.updateGroup(groupEntry);
  }
}
