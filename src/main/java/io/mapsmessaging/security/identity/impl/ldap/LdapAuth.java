/*
 * Copyright [ 2020 - 2024 ] [Matthew Buckton]
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

package io.mapsmessaging.security.identity.impl.ldap;

import io.mapsmessaging.security.identity.GroupEntry;
import io.mapsmessaging.security.identity.IdentityEntry;
import io.mapsmessaging.security.identity.IdentityLookup;
import io.mapsmessaging.security.identity.NoSuchUserFoundException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import javax.naming.Context;

public class LdapAuth implements IdentityLookup {

  private LdapUserManager ldapUserManager;

  public LdapAuth() {
  }

  public LdapAuth(Map<String, ?> config) {
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
  public char[] getPasswordHash(String username) throws NoSuchUserFoundException {
    return ldapUserManager.getPasswordHash(username);
  }

  @Override
  public IdentityEntry findEntry(String username) {
    return ldapUserManager.findEntry(username);
  }

  @Override
  public List<IdentityEntry> getEntries() {
    return new ArrayList<>();
  }

  @Override
  public IdentityLookup create(Map<String, ?> config) {
    if (config.containsKey(Context.PROVIDER_URL)) {
      return new LdapAuth(config);
    }
    return null;
  }

}
