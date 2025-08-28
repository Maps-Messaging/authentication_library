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

package io.mapsmessaging.security.identity.impl.ldap;

import io.mapsmessaging.configuration.ConfigurationProperties;
import io.mapsmessaging.security.identity.GroupEntry;
import io.mapsmessaging.security.identity.IdentityEntry;
import io.mapsmessaging.security.identity.IdentityLookup;
import io.mapsmessaging.security.identity.NoSuchUserFoundException;
import io.mapsmessaging.security.passwords.PasswordBuffer;
import java.util.List;
import javax.naming.Context;

public class LdapAuth implements IdentityLookup {

  private LdapUserManager ldapUserManager;

  public LdapAuth() {
  }

  public LdapAuth(ConfigurationProperties config) {
    ldapUserManager = new LdapUserManager(config);
  }

  @Override
  public String getName() {
    return "ldap";
  }

  @Override
  public String getDomain() {
    return "ldap";
  }

  @Override
  public GroupEntry findGroup(String groupName) {
    return ldapUserManager.findGroup(groupName);
  }

  @Override
  public List<GroupEntry> getGroups() {
    return ldapUserManager.getGroups();
  }

  @Override
  public PasswordBuffer getPasswordHash(String username) throws NoSuchUserFoundException {
    return ldapUserManager.getPasswordHash(username);
  }

  @Override
  public IdentityEntry findEntry(String username) {
    return ldapUserManager.findEntry(username);
  }

  @Override
  public List<IdentityEntry> getEntries() {
    return ldapUserManager.getUsers();
  }

  @Override
  public IdentityLookup create(ConfigurationProperties config) {
    if (config.containsKey(Context.PROVIDER_URL)) {
      return new LdapAuth(config);
    }
    return null;
  }

}
