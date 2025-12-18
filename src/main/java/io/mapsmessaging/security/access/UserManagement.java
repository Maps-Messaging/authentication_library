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

package io.mapsmessaging.security.access;

import com.sun.security.auth.UserPrincipal;
import io.mapsmessaging.security.SubjectHelper;
import io.mapsmessaging.security.access.mapping.UserIdMap;
import io.mapsmessaging.security.access.mapping.UserMapManagement;
import io.mapsmessaging.security.authorisation.AuthorizationProvider;
import io.mapsmessaging.security.identity.IdentityEntry;
import io.mapsmessaging.security.identity.IdentityLookup;
import io.mapsmessaging.security.identity.principals.UniqueIdentifierPrincipal;
import io.mapsmessaging.security.passwords.PasswordHandler;
import io.mapsmessaging.security.uuid.UuidGenerator;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.Principal;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import javax.security.auth.Subject;
import lombok.Getter;

public class UserManagement {

  private final IdentityLookup identityLookup;
  private final UserMapManagement userMapManagement;
  private final GroupManagement groupManagement;
  private final AuthorizationProvider authorizationProvider;
  @Getter
  protected final PasswordHandler passwordHandler;

  public UserManagement(IdentityLookup identityLookup, UserMapManagement userMapManagement, GroupManagement groupManagement, PasswordHandler passwordHandler, AuthorizationProvider authorizationProvider) {
    this.identityLookup = identityLookup;
    this.userMapManagement = userMapManagement;
    this.passwordHandler = passwordHandler;
    this.groupManagement = groupManagement;
    this.authorizationProvider = authorizationProvider;
    for (IdentityEntry entry : identityLookup.getEntries()) {
      mapUser(entry);
    }
  }

  protected IdentityEntry updateSubject(Subject subject, String username) {
    IdentityEntry identityEntry = identityLookup.findEntry(username);
    if (identityEntry == null) {
      return null;
    }
    String key = identityLookup.getDomain() + ":" + username;
    UserIdMap userIdMap = userMapManagement.get(key);
    if (userIdMap == null) {
      userIdMap = mapUser(identityEntry);
      userMapManagement.save();
    }
    Set<Principal> principalSet = subject.getPrincipals();
    principalSet.add(new UniqueIdentifierPrincipal(userIdMap.getAuthId()));
    if(SubjectHelper.getUsername(subject) == null){
      principalSet.add(new UserPrincipal(username));
    }
    return identityEntry;
  }

  public UserIdMap createUser(String username, char[] passwordHash)
      throws IOException, GeneralSecurityException {
    IdentityEntry entry = identityLookup.findEntry(username);
    if (entry != null) {
      throw new GeneralSecurityException("User already exists");
    }
    identityLookup.createUser(username, passwordHash, passwordHandler);

    UserIdMap idMap = userMapManagement.get(identityLookup.getDomain() + ":" + username);
    if (idMap == null) {
      idMap = new UserIdMap(UuidGenerator.getInstance().generate(), username, identityLookup.getDomain());
      userMapManagement.add(idMap);
      userMapManagement.save();
      authorizationProvider.registerIdentity(idMap.getAuthId());
    }
    return idMap;
  }

  public Identity getUser(String username) {
    return buildIdentity(username);
  }

  public List<Identity> getAllUsers() {
    List<Identity> identities = new ArrayList<>();
    for (IdentityEntry entry : identityLookup.getEntries()) {
      identities.add(buildIdentity(entry));
    }
    return identities;
  }

  public boolean deleteUser(String username) throws IOException {
    if (identityLookup.findEntry(username) != null) {
      identityLookup.deleteUser(username);
      UserIdMap userIdMap = getUserMapId(username);
      if (userIdMap != null) {
        authorizationProvider.deleteIdentity(userIdMap.getAuthId());
      }
      userMapManagement.delete(identityLookup.getDomain() + ":" + username);
      userMapManagement.save();
      groupManagement.deleteUserFromAllGroups(username);
      return true;
    }
    return false;
  }

  public boolean updateUserPassword(String username, char[] hash)
      throws IOException, GeneralSecurityException {
    IdentityEntry entry = identityLookup.findEntry(username);
    if (entry != null) {
      identityLookup.deleteUser(username);
      identityLookup.createUser(username, hash, entry.getPasswordHasher());
      return true;
    }
    return false;
  }

  public boolean validateUser(String username, char[] password) throws IOException {
    IdentityEntry entry = identityLookup.findEntry(username);
    if (entry != null) {
      try {
        return entry.getPasswordHasher().matches(password);
      } catch (GeneralSecurityException e) {
        throw new IOException(e);
      }
    }
    return false;
  }

  private UserIdMap getUserMapId(String username) {
    return userMapManagement.get(identityLookup.getDomain() + ":" + username);
  }

  private Identity buildIdentity(String username){
    return buildIdentity(identityLookup.findEntry(username));
  }

  private Identity buildIdentity(IdentityEntry entry){
    if (entry != null ) {
      UserIdMap idMap = getUserMapId(entry.getUsername());
      if(idMap == null){
        idMap = mapUser(entry);
      }
      List<Group> groups = groupManagement.getGroups(entry.getGroups());
      return new Identity(idMap.getAuthId(), entry, groups);
    }
    return null;
  }

  protected UserIdMap mapUser(IdentityEntry entry) {
    UserIdMap userIdMap = null;
    if (userMapManagement.get(entry.getUsername()) == null) {
      userIdMap = new UserIdMap(UuidGenerator.getInstance().generate(), entry.getUsername(), identityLookup.getDomain());
      userMapManagement.add(userIdMap);
    }
    groupManagement.mapUserToAllGroups(entry);
    return userIdMap;
  }
}
