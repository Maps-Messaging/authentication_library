/*
 *
 *  Copyright [ 2020 - 2024 ] [Matthew Buckton]
 *  Copyright [ 2024 - 2025 ] [Maps Messaging B.V.]
 *
 *   Licensed under the Apache License, Version 2.0 (the "License");
 *   you may not use this file except in compliance with the License.
 *   You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */

package io.mapsmessaging.security.identity.impl.auth0;

import static io.mapsmessaging.security.logging.AuthLogMessages.AUTH0_FAILURE;
import static io.mapsmessaging.security.logging.AuthLogMessages.AUTH0_REQUEST_FAILURE;

import com.auth0.client.auth.AuthAPI;
import com.auth0.client.mgmt.ManagementAPI;
import com.auth0.exception.Auth0Exception;
import com.auth0.json.auth.TokenHolder;
import com.auth0.json.mgmt.roles.Role;
import com.auth0.json.mgmt.users.User;
import com.auth0.net.TokenRequest;
import io.mapsmessaging.configuration.ConfigurationProperties;
import io.mapsmessaging.logging.Logger;
import io.mapsmessaging.logging.LoggerFactory;
import io.mapsmessaging.security.identity.GroupEntry;
import io.mapsmessaging.security.identity.IdentityEntry;
import io.mapsmessaging.security.identity.IdentityLookup;
import io.mapsmessaging.security.identity.NoSuchUserFoundException;
import io.mapsmessaging.security.identity.impl.external.CachingIdentityLookup;
import io.mapsmessaging.security.passwords.PasswordBuffer;
import java.util.ArrayList;
import java.util.List;
import lombok.Getter;

public class Auth0Auth extends CachingIdentityLookup<Auth0IdentityEntry> {

  private final Logger logger = LoggerFactory.getLogger(Auth0Auth.class);
  private final String clientId;
  private final String clientSecret;
  private final String apiToken;

  private final Auth0Api auth0Api;
  @Getter
  private final AuthAPI authAPI;
  private final ManagementAPI mgmt;
  @Getter
  private final String auth0Domain;

  private long cacheTime = 30000;

  public Auth0Auth() {
    auth0Domain = "";
    clientId = "";
    clientSecret = "";
    apiToken = "";
    auth0Api = null;
    authAPI = null;
    mgmt = null;
  }

  public Auth0Auth(ConfigurationProperties config) {
    auth0Domain = config.getProperty("domain");
    clientId = config.getProperty("clientId");
    clientSecret = config.getProperty("clientSecret");
    String cacheTimeString = config.getProperty("cacheTime");
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
      logger.log(AUTH0_REQUEST_FAILURE, e);
    }
    apiToken = token;
    mgmt = ManagementAPI.newBuilder(auth0Domain, apiToken).build();
    auth0Api = new Auth0Api(mgmt, cacheTime);
  }

  @Override
  public IdentityLookup create(ConfigurationProperties config) {
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
  public PasswordBuffer getPasswordHash(String username) throws NoSuchUserFoundException {
    return new PasswordBuffer(new char[0]);
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
      logger.log(AUTH0_FAILURE, e);
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
      logger.log(AUTH0_FAILURE,ex);
    }
    loadGroups();
  }
}
