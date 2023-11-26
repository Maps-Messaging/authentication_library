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

package io.mapsmessaging.security.access.permission;

import io.mapsmessaging.security.SubjectHelper;
import io.mapsmessaging.security.access.AccessControlList;
import io.mapsmessaging.security.access.AccessControlListParser;
import io.mapsmessaging.security.access.AccessControlMapping;
import io.mapsmessaging.security.access.AclEntry;
import io.mapsmessaging.security.identity.principals.GroupPrincipal;

import javax.security.auth.Subject;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.UUID;

public class PermissionAccessControlList implements AccessControlList {

  private final List<AclEntry> aclEntries;

  public PermissionAccessControlList() {
    aclEntries = new ArrayList<>();
  }

  public PermissionAccessControlList(List<AclEntry> aclEntries) {
    this.aclEntries = new ArrayList<>(aclEntries);
  }

  @Override
  public String getName() {
    return "permission";
  }

  @Override
  public AccessControlList create(AccessControlMapping accessControlMapping, List<String> config) {
    AccessControlListParser parser = new AccessControlListParser();
    return new PermissionAccessControlList(parser.createList(accessControlMapping, config));
  }

  public long getSubjectAccess(Subject subject) {
    long mask = 0;
    if (subject != null) {
      long time = System.currentTimeMillis();
      UUID authId = SubjectHelper.getUniqueId(subject);
      for (AclEntry aclEntry : aclEntries) {
        if (!aclEntry.getExpiryPolicy().hasExpired(time) &&
            aclEntry.matches(authId)) {
          mask = mask | aclEntry.getPermissions();
        }
      }

      // Scan the groups for access
      Set<GroupPrincipal> groups = subject.getPrincipals(GroupPrincipal.class);
      for (GroupPrincipal group : groups) {
        for (AclEntry aclEntry : aclEntries) {
          //ToDo check that the group is in the aclEntry
          if (!aclEntry.getExpiryPolicy().hasExpired(time)) {//&& aclEntry.matches(group.getUuid())) {
            mask = mask | aclEntry.getPermissions();
          }
        }
      }
    }
    return mask;
  }

  public boolean canAccess(Subject subject, long requestedAccess) {
    if (subject == null || requestedAccess == 0) {
      return false;
    }
    UUID authId = SubjectHelper.getUniqueId(subject);

    // Scan for authId for access
    for (AclEntry aclEntry : aclEntries) {
      if ((aclEntry.getPermissions() & requestedAccess) == requestedAccess
          && aclEntry.matches(authId)) {
        return true;
      }
    }

    // Scan the groups for access
    Set<GroupPrincipal> groups = subject.getPrincipals(GroupPrincipal.class);
    for (GroupPrincipal group : groups) {
      for (AclEntry aclEntry : aclEntries) {
        if ((aclEntry.getPermissions() & requestedAccess) == requestedAccess) {//&& aclEntry.matches(group.getUuid())) {
          return true;
        }
      }
    }
    // This means neither user nor group has access
    return false;
  }
}