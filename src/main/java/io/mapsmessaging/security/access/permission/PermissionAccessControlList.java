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

package io.mapsmessaging.security.access.permission;

import io.mapsmessaging.security.SubjectHelper;
import io.mapsmessaging.security.access.AccessControlList;
import io.mapsmessaging.security.access.AccessControlListParser;
import io.mapsmessaging.security.access.AccessControlMapping;
import io.mapsmessaging.security.access.AclEntry;
import io.mapsmessaging.security.access.mapping.GroupIdMap;
import io.mapsmessaging.security.identity.principals.GroupIdPrincipal;
import java.util.*;
import javax.security.auth.Subject;

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
      mask = processAclEntriesForSubject(subject, time);

      Set<GroupIdPrincipal> groups = subject.getPrincipals(GroupIdPrincipal.class);
      mask |= processGroups(groups, time);
    }
    return mask;
  }

  private long processAclEntriesForSubject(Subject subject, long time) {
    UUID authId = SubjectHelper.getUniqueId(subject);
    return aclEntries.stream()
        .filter(aclEntry -> isValidAclEntry(aclEntry, time, authId))
        .mapToLong(AclEntry::getPermissions)
        .reduce(0, (a, b) -> a | b);
  }

  private long processGroups(Set<GroupIdPrincipal> groups, long time) {
    return groups.stream()
        .flatMap(group -> group.getGroupIds().stream())
        .mapToLong(groupIdMap -> processAclEntriesForGroupId(groupIdMap, time))
        .reduce(0, (a, b) -> a | b);
  }

  private long processAclEntriesForGroupId(GroupIdMap groupIdMap, long time) {
    return aclEntries.stream()
        .filter(aclEntry -> isValidAclEntry(aclEntry, time, groupIdMap.getAuthId()))
        .mapToLong(AclEntry::getPermissions)
        .reduce(0, (a, b) -> a | b);
  }

  private boolean isValidAclEntry(AclEntry aclEntry, long time, UUID authId) {
    return !aclEntry.getExpiryPolicy().hasExpired(time) && aclEntry.matches(authId);
  }

  // We are exiting early here because we want to fast exit once we found access is allowed
  @SuppressWarnings("java:S3516")
  public boolean canAccess(Subject subject, long requestedAccess) {
    if (subject == null || requestedAccess == 0) {
      return false;
    }

    UUID authId = SubjectHelper.getUniqueId(subject);
    if (checkAccessForId(authId, requestedAccess)) {
      return true;
    }

    if (!subject.getPrincipals(GroupIdPrincipal.class).isEmpty()) {
      for (GroupIdPrincipal group : subject.getPrincipals(GroupIdPrincipal.class)) {
        for (GroupIdMap groupIdMap : group.getGroupIds()) {
          if (checkAccessForId(groupIdMap.getAuthId(), requestedAccess)) {
            return true;
          }
        }
      }
    }
    return false;
  }

  @Override
  public boolean add(UUID uuid, long requestedAccess) {
    AclEntry entry = new AclEntry(uuid, requestedAccess);
    aclEntries.add(entry);
    return true;
  }

  @Override
  public boolean remove(UUID uuid, long requestedAccess) {
    aclEntries.removeIf(entry -> entry.matches(uuid));
    return true;
  }


  // We are exiting early here because we want to fast exit once we found access is allowed
  @SuppressWarnings("java:S3516")
  private boolean checkAccessForId(UUID id, long requestedAccess) {
    for (AclEntry aclEntry : aclEntries) {
      if(isAccessGranted(aclEntry, requestedAccess, id)){
        return true;
      }
    }
    return false;
  }

  private boolean isAccessGranted(AclEntry aclEntry, long requestedAccess, UUID authId) {
    return (aclEntry.getPermissions() & requestedAccess) == requestedAccess && aclEntry.matches(authId);
  }

}