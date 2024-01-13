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
import com.auth0.exception.Auth0Exception;
import com.auth0.json.auth.TokenHolder;
import com.auth0.json.mgmt.roles.Role;
import com.auth0.json.mgmt.users.User;
import com.auth0.net.TokenRequest;
import io.mapsmessaging.security.identity.GroupEntry;
import io.mapsmessaging.security.identity.IdentityEntry;
import io.mapsmessaging.security.identity.IdentityLookup;
import io.mapsmessaging.security.identity.NoSuchUserFoundException;
import io.mapsmessaging.security.identity.impl.external.CachingIdentityLookup;
import io.mapsmessaging.security.passwords.PasswordHandler;
import lombok.Getter;
import lombok.Setter;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

@Getter
@Setter
public class Auth0Auth extends CachingIdentityLookup<Auth0IdentityEntry> {

  private final String auth0Domain;
  private final String clientId;
  private final String clientSecret;
  private final String authToken;
  private final String apiToken;

  private final Auth0Api auth0Api;
  private final AuthAPI authAPI;
  private final ManagementAPI mgmt;

  private long cacheTime = 30000;

  public Auth0Auth() {
    auth0Domain = "";
    clientId = "";
    clientSecret = "";
    authToken = "";
    apiToken = "";
    auth0Api = null;
    authAPI = null;
    mgmt = null;
  }

  public Auth0Auth(Map<String, ?> config) {
    auth0Domain = (String) config.get("domain");
    clientId = (String) config.get("clientId");
    clientSecret = (String) config.get("clientSecret");
    authToken = (String) config.get("authToken");
    String cacheTimeString = (String) config.get("cacheTime");
    if (cacheTimeString != null && !cacheTimeString.trim().isEmpty()) {
      cacheTime = Long.parseLong(cacheTimeString.trim());
    }
    authAPI = AuthAPI.newBuilder(auth0Domain, clientId, clientSecret).build();
    TokenRequest tokenRequest = authAPI.requestToken("https://" + auth0Domain + "/api/v2/");
    String token = "";
    try {
      TokenHolder holder = tokenRequest.execute().getBody();
      token = holder.getAccessToken();
    } catch (Auth0Exception e) {
      // ToDo add logging
    }
    apiToken = token;
    mgmt = ManagementAPI.newBuilder(auth0Domain, apiToken).build();
    auth0Api = new Auth0Api(mgmt, cacheTime);
  }

  @Override
  public IdentityLookup create(Map<String, ?> config) {
    return new Auth0Auth(config);
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
  protected IdentityEntry createIdentityEntry(String username) {
    return new Auth0IdentityEntry(this, username);
  }

  @Override
  public List<IdentityEntry> getEntries() {
    loadUsers();
    return new ArrayList<>(identityEntries);
  }

  @Override
  public GroupEntry findGroup(String groupName) {
    return groupEntryMap.get(groupName);
  }

  @Override
  public List<GroupEntry> getGroups() {
    return new ArrayList<>(groupEntryMap.values());
  }

  @Override
  public boolean createGroup(String groupName) throws IOException {
    return super.createGroup(groupName);
  }

  @Override
  public boolean deleteGroup(String groupName) throws IOException {
    return super.deleteGroup(groupName);
  }

  @Override
  public boolean createUser(String username, String passwordHash, PasswordHandler passwordHasher)
      throws IOException {
    return super.createUser(username, passwordHash, passwordHasher);
  }

  @Override
  public boolean deleteUser(String username) throws IOException {
    return super.deleteUser(username);
  }

  @Override
  public void updateGroup(GroupEntry groupEntry) throws IOException {
    super.updateGroup(groupEntry);
  }

  @Override
  protected void loadGroups(Auth0IdentityEntry identityEntry) {
    loadGroups();
  }

  private void loadGroups() {
    if (auth0Api.isGroupCacheValid()) {
      return;
    }
    groupEntryMap.clear();
    try {
      List<Role> roles = auth0Api.getGroupList();
      for (Role role : roles) {
        Auth0GroupEntry groupEntry = new Auth0GroupEntry(role.getName());

        List<String> users = auth0Api.getUserInGroup(role.getId());
        for (String user : users) {
          Auth0IdentityEntry identityEntry = identityEntryMap.get(user);
          if (identityEntry != null) {
            groupEntry.addUser(user);
            identityEntry.addGroup(groupEntry);
          }
        }
        groupEntryMap.put(role.getName(), groupEntry);
      }
    } catch (Auth0Exception e) {
      throw new RuntimeException(e);
    }
  }

  @Override
  protected void loadUsers() {
    if (auth0Api.isUserCacheValid()) {
      return;
    }
    identityEntryMap.clear();
    identityEntries.clear();
    try {
      List<User> response = auth0Api.getUserList();
      for (User user : response) {
        Auth0IdentityEntry entry = new Auth0IdentityEntry(this, user.getEmail());
        identityEntryMap.put(user.getEmail(), entry);
        identityEntries.add(entry);
      }
    } catch (Exception ex) {
      // todo
      ex.printStackTrace();
    }
    loadGroups();
  }
}
