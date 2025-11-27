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

package io.mapsmessaging.security.authorisation.impl.acl;

import io.mapsmessaging.security.access.Group;
import io.mapsmessaging.security.access.Identity;
import io.mapsmessaging.security.authorisation.Access;
import java.util.*;

public class AccessControlList {

  private final List<AclEntry> aclEntries;

  public AccessControlList() {
    aclEntries = new ArrayList<>();
  }

  public AccessControlList(List<String> aclEntries) {
    AccessControlListParser parser = new AccessControlListParser();
    this.aclEntries = new ArrayList<>(parser.createList(aclEntries));
  }

  public AccessControlList create(List<String> config) {
    return new AccessControlList(config);
  }

  public long getSubjectAccess(Identity identity) {
    long mask = 0;
    if (identity != null) {
      mask = processAclEntriesForSubject(identity.getId());
      mask |= processGroups(identity.getGroupList());
    }
    return mask;
  }

  public long getGroupAccess(Group group) {
    return processGroups(List.of(group));
  }

  public long getRawAccess(UUID uuid) {
    return processAclEntriesForSubject(uuid);
  }

  private long processAclEntriesForSubject(UUID authId) {
    return aclEntries.stream()
        .filter(aclEntry -> isValidAclEntry(aclEntry, authId))
        .mapToLong(AclEntry::getAllow)
        .reduce(0, (a, b) -> a | b);
  }

  private long processGroups(List<Group> groups) {
    return groups.stream()
        .mapToLong(groupIdMap -> processAclEntriesForGroupId(groupIdMap))
        .reduce(0, (a, b) -> a | b);
  }

  private long processAclEntriesForGroupId(Group group) {
    return aclEntries.stream()
        .filter(aclEntry -> isValidAclEntry(aclEntry, group.getId()))
        .mapToLong(AclEntry::getAllow)
        .reduce(0, (a, b) -> a | b);
  }

  private boolean isValidAclEntry(AclEntry aclEntry, UUID authId) {
    return aclEntry.matches(authId);
  }

  // We are exiting early here because we want to fast exit once we found access is allowed
  @SuppressWarnings("java:S3516")
  public Access canAccess(Identity identity, long requestedAccess) {
    UUID authId = identity.getId();
    Access access = checkAccessForId(authId, requestedAccess);
    if (access != Access.UNKNOWN) {
      return access;
    }

    if (!identity.getGroupList().isEmpty()) {
      for (Group group : identity.getGroupList()) {
        Access groupAccess = checkAccessForId(group.getId(), requestedAccess);
        if(groupAccess != Access.UNKNOWN) {
          return groupAccess;
        }
      }
    }
    return access;
  }

  public boolean addUser(UUID uuid, long requestedAccess) {
    AclEntry entry = findOrCreate(uuid, false);
    entry.setAllow(entry.getAllow() | requestedAccess);
    entry.setDeny(entry.getDeny() | 0L);
    return true;
  }

  public boolean addGroup(UUID uuid, long requestedAccess) {
    AclEntry entry = findOrCreate(uuid, true);
    entry.setAllow(entry.getAllow() | requestedAccess);
    entry.setDeny(entry.getDeny() | 0L);
    return true;
  }

  public boolean remove(UUID uuid, long requestedAccess) {
    AclEntry entry = null;
    for (AclEntry aclEntry : aclEntries) {
      if (aclEntry.matches(uuid)) {
        entry = aclEntry;
        break;
      }
    }
    if (entry != null) {
      entry.setAllow(entry.getAllow() & ~requestedAccess);
      entry.setDeny(entry.getDeny() & ~requestedAccess);
      if (entry.getAllow() == 0 && entry.getDeny() == 0) {
        aclEntries.remove(entry);
        return true;
      }
    }
    return false;
  }

  public List<AclEntry> getAclEntries() {
    return new ArrayList<>(aclEntries);
  }

  // We are exiting early here because we want to fast exit once we found access is allowed
  @SuppressWarnings("java:S3516")
  private Access checkAccessForId(UUID id, long requestedAccess) {
    AclEntry aclEntry = find(id);
    if (aclEntry != null) {
      return isAccessGranted(aclEntry, requestedAccess, id);
    }
    return Access.UNKNOWN;
  }

  private Access isAccessGranted(AclEntry aclEntry, long requestedAccess, UUID authId) {
    if (aclEntry.matches(authId)) {
      if ((aclEntry.getAllow() & requestedAccess) != 0) {
        return Access.ALLOW;
      } else if ((aclEntry.getDeny() & requestedAccess) != 0) {
        return Access.DENY;
      }
    }
    return Access.UNKNOWN;
  }

  private AclEntry find(UUID uuid) {
    return aclEntries.stream()
        .filter(e -> e.matches(uuid))
        .findFirst()
        .orElse(null);
  }


  private AclEntry findOrCreate(UUID authId, boolean isGroup) {
    AclEntry newEntry = find(authId);
    if(newEntry != null) {
      return newEntry;
    }
    newEntry = new AclEntry(authId, isGroup, 0L, 0L);
    aclEntries.add(newEntry);
    return newEntry;
  }
}