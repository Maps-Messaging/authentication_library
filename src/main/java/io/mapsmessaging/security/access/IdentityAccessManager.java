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

package io.mapsmessaging.security.access;

import io.mapsmessaging.security.SubjectHelper;
import io.mapsmessaging.security.access.mapping.GroupIdMap;
import io.mapsmessaging.security.access.mapping.GroupMapManagement;
import io.mapsmessaging.security.access.mapping.UserIdMap;
import io.mapsmessaging.security.access.mapping.UserMapManagement;
import io.mapsmessaging.security.access.mapping.store.MapStore;
import io.mapsmessaging.security.identity.GroupEntry;
import io.mapsmessaging.security.identity.IdentityEntry;
import io.mapsmessaging.security.identity.IdentityLookup;
import io.mapsmessaging.security.identity.IdentityLookupFactory;
import io.mapsmessaging.security.identity.impl.encrypted.EncryptedAuth;
import io.mapsmessaging.security.identity.principals.GroupIdPrincipal;
import io.mapsmessaging.security.identity.principals.UniqueIdentifierPrincipal;
import io.mapsmessaging.security.passwords.PasswordHandler;
import io.mapsmessaging.security.passwords.PasswordHandlerFactory;
import io.mapsmessaging.security.passwords.ciphers.EncryptedPasswordCipher;
import io.mapsmessaging.security.uuid.UuidGenerator;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.Principal;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import javax.security.auth.Subject;
import lombok.Getter;
import lombok.Setter;

public class IdentityAccessManager {

  @Getter private final IdentityLookup identityLookup;
  private final GroupMapManagement groupMapManagement;
  private final UserMapManagement userMapManagement;

  @Getter @Setter private PasswordHandler passwordHandler;

  public IdentityAccessManager(
      String identity,
      Map<String, Object> config,
      MapStore<UserIdMap> userStore,
      MapStore<GroupIdMap> groupStore) {
    identityLookup = IdentityLookupFactory.getInstance().get(identity, config);
    groupMapManagement = new GroupMapManagement(groupStore);
    userMapManagement = new UserMapManagement(userStore);
    for (IdentityEntry entry : identityLookup.getEntries()) {
      mapUser(entry);
    }
    String handlerName = (String) config.get("passwordHandler");
    if (handlerName == null || handlerName.isEmpty()) {
      handlerName = "Pbkdf2Sha512PasswordHasher";
    }
    PasswordHandler baseHandler = PasswordHandlerFactory.getInstance().getByClassName(handlerName);
    if (baseHandler instanceof EncryptedPasswordCipher && identityLookup instanceof EncryptedAuth) {
      passwordHandler = ((EncryptedAuth) identityLookup).getPasswordHandler();
    } else {
      passwordHandler = baseHandler;
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
    String key = identityLookup.getDomain() + ":" + username;
    UserIdMap userIdMap = userMapManagement.get(key);
    if (userIdMap == null) {
      userIdMap = mapUser(identityEntry);
      userMapManagement.save();
      groupMapManagement.save();
    }
    Set<Principal> principalSet = subject.getPrincipals();
    principalSet.add(new UniqueIdentifierPrincipal(userIdMap.getAuthId()));
    List<GroupIdMap> groups = new ArrayList<>();
    for (GroupEntry groupEntry : identityEntry.getGroups()) {
      String gKey = identityLookup.getDomain() + ":" + groupEntry.getName();
      GroupIdMap groupIdMap = groupMapManagement.get(gKey);
      if (groupIdMap != null) {
        groups.add(groupIdMap);
      }
    }

    principalSet.add(new GroupIdPrincipal(groups));
    return subject;
  }

  public GroupIdMap createGroup(String groupName) throws IOException {
    GroupEntry groupEntry = identityLookup.findGroup(groupName);
    GroupIdMap groupIdMap = groupMapManagement.get(identityLookup.getDomain() + ":" + groupName);
    if (groupEntry != null && groupIdMap != null) {
      return groupIdMap;
    }
    if (groupEntry == null) {
      identityLookup.createGroup(groupName);
    }
    if (groupIdMap == null) {
      groupIdMap = new GroupIdMap(UuidGenerator.getInstance().generate(), groupName, identityLookup.getDomain());
      groupMapManagement.add(groupIdMap);
      groupMapManagement.save();
    }
    return groupIdMap;
  }

  public boolean deleteGroup(String groupName) throws IOException {
    GroupEntry groupEntry = identityLookup.findGroup(groupName);
    if (groupEntry != null) {
      identityLookup.deleteGroup(groupName);
      groupMapManagement.delete(identityLookup.getDomain() + ":" + groupName);
      groupMapManagement.save();
      return true;
    }
    return false;
  }

  public UserIdMap getUser(String username) {
    return userMapManagement.get(identityLookup.getDomain() + ":" + username);
  }

  public GroupIdMap getGroup(String groupName) {
    return groupMapManagement.get(identityLookup.getDomain() + ":" + groupName);
  }

  public GroupEntry getGroupDetails(String groupName) {
    return identityLookup.findGroup(groupName);
  }

  public UserIdMap createUser(String username, String hash)
      throws IOException, GeneralSecurityException {
    IdentityEntry entry = identityLookup.findEntry(username);
    UserIdMap idMap = userMapManagement.get(identityLookup.getDomain() + ":" + username);
    if (entry != null && idMap != null) {
      return idMap;
    }
    if (entry == null) {
      identityLookup.createUser(username, hash, passwordHandler);
    }
    if (idMap == null) {
      idMap = new UserIdMap(UuidGenerator.getInstance().generate(), username, identityLookup.getDomain());
      userMapManagement.add(idMap);
      userMapManagement.save();
    }
    return idMap;
  }

  public boolean updateUserPassword(String username, String hash, PasswordHandler passwordHasher)
      throws IOException, GeneralSecurityException {
    if (identityLookup.findEntry(username) != null) {
      identityLookup.deleteUser(username);
      identityLookup.createUser(username, hash, passwordHasher);
      return true;
    }
    return false;
  }

  public IdentityEntry getUserIdentity(String username) {
    return identityLookup.findEntry(username);
  }

  public boolean deleteUser(String username) throws IOException {
    if (identityLookup.findEntry(username) != null) {
      identityLookup.deleteUser(username);
      userMapManagement.delete(identityLookup.getDomain() + ":" + username);
      userMapManagement.save();
      for (GroupEntry groupEntry : identityLookup.getGroups()) {
        if (groupEntry.isInGroup(username)) {
          groupEntry.removeUser(username);
          if (groupEntry.getUserCount() == 0) {
            identityLookup.deleteGroup(groupEntry.getName());
            groupMapManagement.delete(groupEntry.getName());
          }
          identityLookup.updateGroup(groupEntry);
        }
      }
      groupMapManagement.save();
      return true;
    }
    return false;
  }

  public boolean addUserToGroup(String username, String group) throws IOException {
    IdentityEntry identityEntry = identityLookup.findEntry(username);
    if (identityEntry == null) {
      return false;
    }
    GroupEntry groupEntry = identityLookup.findGroup(group);
    if (groupEntry == null) {
      return false;
    }
    if (identityEntry.isInGroup(groupEntry.getName())) {
      return false;
    }
    identityEntry.addGroup(groupEntry);
    groupEntry.addUser(username);
    identityLookup.updateGroup(groupEntry);
    return true;
  }

  public boolean removeUserFromGroup(String username, String group) throws IOException {
    IdentityEntry identityEntry = identityLookup.findEntry(username);
    if (identityEntry == null) {
      return false;
    }
    GroupEntry groupEntry = identityLookup.findGroup(group);
    if (groupEntry == null) {
      return false;
    }
    if (!identityEntry.isInGroup(groupEntry.getName())) {
      return false;
    }
    identityEntry.removeGroup(groupEntry);
    groupEntry.removeUser(username);
    identityLookup.updateGroup(groupEntry);
    if (groupEntry.getUserCount() == 0) {
      identityLookup.deleteGroup(groupEntry.getName());
      groupMapManagement.delete(groupEntry.getName());
      groupMapManagement.save();
    }
    return true;

  }

  private UserIdMap mapUser(IdentityEntry entry) {
    UserIdMap userIdMap = null;
    if (userMapManagement.get(entry.getUsername()) == null) {
      userIdMap = new UserIdMap(UuidGenerator.getInstance().generate(), entry.getUsername(), identityLookup.getDomain());
      userMapManagement.add(userIdMap);
    }
    for (GroupEntry group : entry.getGroups()) {
      if (groupMapManagement.get(group.getName()) == null) {
        GroupIdMap groupIdMap = new GroupIdMap(UuidGenerator.getInstance().generate(), group.getName(), identityLookup.getDomain());
        groupMapManagement.add(groupIdMap);
      }
    }
    return userIdMap;
  }
}
