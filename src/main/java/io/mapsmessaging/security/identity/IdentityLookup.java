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

package io.mapsmessaging.security.identity;

import io.mapsmessaging.security.identity.parsers.PasswordParser;
import org.apache.commons.lang3.NotImplementedException;

import java.io.IOException;
import java.util.List;
import java.util.Map;

public interface IdentityLookup {

  String getName();

  String getDomain();

  char[] getPasswordHash(String username) throws NoSuchUserFoundException;

  IdentityEntry findEntry(String username);

  GroupEntry findGroup(String groupName);

  List<IdentityEntry> getEntries();

  IdentityLookup create(Map<String, ?> config);

  default boolean createGroup(String groupName) throws IOException {
    throw new NotImplementedException("Unable to add groups");
  }

  default boolean deleteGroup(String groupName) throws IOException {
    throw new NotImplementedException("Unable to delete groups");
  }

  default boolean createUser(String username, String passwordHash, PasswordParser passwordParser) throws IOException {
    throw new NotImplementedException("Unable to add users to an LDAP server");
  }

  default boolean deleteUser(String username) throws IOException {
    throw new NotImplementedException("Unable to delete users to an LDAP server");
  }

  default void updateGroup(GroupEntry groupEntry) throws IOException {
    throw new NotImplementedException("Unable to delete users to an LDAP server");
  }
}
