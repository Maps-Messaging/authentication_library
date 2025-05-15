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

package io.mapsmessaging.security.identity;

import io.mapsmessaging.configuration.ConfigurationProperties;
import io.mapsmessaging.security.passwords.PasswordBuffer;
import io.mapsmessaging.security.passwords.PasswordHandler;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.List;
import org.apache.commons.lang3.NotImplementedException;

public interface IdentityLookup {

  String getName();

  String getDomain();

  PasswordBuffer getPasswordHash(String username) throws IOException, GeneralSecurityException;

  IdentityEntry findEntry(String username);

  List<IdentityEntry> getEntries();

  GroupEntry findGroup(String groupName);

  List<GroupEntry> getGroups();

  IdentityLookup create(ConfigurationProperties config);

  default boolean createGroup(String groupName) throws IOException {
    throw new NotImplementedException("Unable to add groups");
  }

  default boolean deleteGroup(String groupName) throws IOException {
    throw new NotImplementedException("Unable to delete groups");
  }

  default boolean createUser(String username, char[] passwordHash, PasswordHandler passwordHasher)
      throws IOException, GeneralSecurityException {
    throw new NotImplementedException("Unable to add users to an LDAP server");
  }

  default boolean deleteUser(String username) throws IOException {
    throw new NotImplementedException("Unable to delete users to an LDAP server");
  }

  default void updateGroup(GroupEntry groupEntry) throws IOException {
    throw new NotImplementedException("Unable to delete users to an LDAP server");
  }

  default boolean canManage(){
    return false;
  }
}
