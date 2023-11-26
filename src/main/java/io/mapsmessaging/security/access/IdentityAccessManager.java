/*
 * Copyright [ 2020 - 2023 ] [Matthew Buckton]
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package io.mapsmessaging.security.access;

import io.mapsmessaging.security.SubjectHelper;
import io.mapsmessaging.security.access.mapping.GroupIdMap;
import io.mapsmessaging.security.access.mapping.GroupMapManagement;
import io.mapsmessaging.security.access.mapping.UserIdMap;
import io.mapsmessaging.security.access.mapping.UserMapManagement;
import io.mapsmessaging.security.identity.GroupEntry;
import io.mapsmessaging.security.identity.IdentityEntry;
import io.mapsmessaging.security.identity.IdentityLookup;
import io.mapsmessaging.security.identity.IdentityLookupFactory;
import io.mapsmessaging.security.identity.parsers.PasswordParser;
import io.mapsmessaging.security.identity.principals.GroupIdPrincipal;
import io.mapsmessaging.security.identity.principals.UniqueIdentifierPrincipal;

import javax.security.auth.Subject;
import java.io.File;
import java.io.IOException;
import java.security.Principal;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

public class IdentityAccessManager {

  private final IdentityLookup identityLookup;
  private final GroupMapManagement groupMapManagement;
  private final UserMapManagement userMapManagement;

  public IdentityAccessManager(String identity, Map<String, ?> config) {
    String path = (String) config.get("configDirectory");
    identityLookup = IdentityLookupFactory.getInstance().get(identity, config);
    groupMapManagement = new GroupMapManagement(path + File.separator + "groupmap");
    userMapManagement = new UserMapManagement(path + File.separator + "usermap");
    for (IdentityEntry entry : identityLookup.getEntries()) {
      mapUser(entry);
    }
    userMapManagement.save();
    groupMapManagement.save();
  }

  public List<UserIdMap> getAllUsers() {
    return userMapManagement.getAll();
  }

  public List<GroupIdMap> getAllGroups() {
    return groupMapManagement.getAll();
  }

  public Subject updateSubject(Subject subject) {
    String username = SubjectHelper.getUsername(subject);
    IdentityEntry identityEntry = identityLookup.findEntry(username);
    if (identityEntry == null) {
      return null;
    }
    UserIdMap userIdMap = userMapManagement.get(username);
    if (userIdMap == null) {
      userIdMap = mapUser(identityEntry);
      userMapManagement.save();
      groupMapManagement.save();
    }
    Set<Principal> principalSet = subject.getPrincipals();
    principalSet.add(new UniqueIdentifierPrincipal(userIdMap.getAuthId()));
    for (GroupEntry groupEntry : identityEntry.getGroups()) {
      GroupIdMap groupIdMap = groupMapManagement.get(groupEntry.getName());
      if (groupIdMap != null) {
        principalSet.add(new GroupIdPrincipal(groupIdMap.getAuthId()));
      }
    }
    return subject;
  }

  public boolean createGroup(String groupName) throws IOException {
    if (groupMapManagement.get(groupName) != null) {
      return false;
    }
    GroupIdMap groupIdMap = new GroupIdMap(UUID.randomUUID(), groupName, identityLookup.getDomain());
    identityLookup.createGroup(groupName);
    groupMapManagement.add(groupIdMap);
    groupMapManagement.save();
    return true;
  }

  public boolean deleteGroup(String groupName) throws IOException {
    if (groupMapManagement.get(groupName) != null) {
      if (identityLookup.deleteGroup(groupName)) {
        groupMapManagement.remove(groupName);
        groupMapManagement.save();
        return true;
      }
    }
    return false;
  }

  public boolean createUser(String username, String hash, PasswordParser passwordParser) throws IOException {
    if (identityLookup.findEntry(username) != null) {
      return false;
    }
    identityLookup.createUser(username, hash, passwordParser);
    UserIdMap userIdMap = new UserIdMap(UUID.randomUUID(), username, identityLookup.getDomain(), null);
    userMapManagement.add(userIdMap);
    userMapManagement.save();
    return true;
  }

  public boolean updateUserPassword(String username, String hash, PasswordParser passwordParser) throws IOException {
    if (identityLookup.findEntry(username) != null) {
      identityLookup.deleteUser(username);
      identityLookup.createUser(username, hash, passwordParser);
      return true;
    }
    return false;
  }

  public boolean deleteUser(String username) throws IOException {
    if (identityLookup.findEntry(username) != null) {
      identityLookup.deleteUser(username);
      userMapManagement.remove(username);
      userMapManagement.save();
      return true;
    }
    return false;
  }

  private UserIdMap mapUser(IdentityEntry entry) {
    UserIdMap userIdMap = null;
    if (userMapManagement.get(entry.getUsername()) == null) {
      userIdMap = new UserIdMap(UUID.randomUUID(), entry.getUsername(), identityLookup.getDomain(), null);
      userMapManagement.add(userIdMap);
    }
    for (GroupEntry group : entry.getGroups()) {
      if (groupMapManagement.get(group.getName()) == null) {
        GroupIdMap groupIdMap = new GroupIdMap(UUID.randomUUID(), group.getName(), identityLookup.getDomain());
        groupMapManagement.add(groupIdMap);
      }
    }
    return userIdMap;
  }
}
