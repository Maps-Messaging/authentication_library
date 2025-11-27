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

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicBoolean;

public class AccessControlList {

  private final Map<UUID, AclEntry> aclEntries;

  public AccessControlList() {
    aclEntries = new ConcurrentHashMap<>();
  }

  public AccessControlList(List<String> config) {
    this.aclEntries = new ConcurrentHashMap<>();
    AccessControlListParser parser = new AccessControlListParser();
    List<AclEntry> parsedAclEntries = parser.createList(config);
    for(AclEntry aclEntry: parsedAclEntries){
      aclEntries.put(aclEntry.getAuthId(), aclEntry);
    }
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
    return aclEntries.values().stream()
        .filter(aclEntry -> isValidAclEntry(aclEntry, authId))
        .mapToLong(AclEntry::getAllow)
        .reduce(0L, (a, b) -> a | b);
  }

  private long processGroups(List<Group> groups) {
    return groups.stream()
        .mapToLong(this::processAclEntriesForGroupId)
        .reduce(0L, (a, b) -> a | b);
  }

  private long processAclEntriesForGroupId(Group group) {
    return aclEntries.values().stream()
        .filter(aclEntry -> isValidAclEntry(aclEntry, group.getId()))
        .mapToLong(AclEntry::getAllow)
        .reduce(0L, (a, b) -> a | b);
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
        if (groupAccess != Access.UNKNOWN) {
          return groupAccess;
        }
      }
    }
    return access;
  }

  public boolean addUser(UUID uuid, long requestedAccess, boolean grant) {
    return addEntry(uuid, requestedAccess, grant, false);
  }

  public boolean addGroup(UUID uuid, long requestedAccess, boolean grant) {
    return addEntry(uuid, requestedAccess, grant, true);
  }

  private boolean addEntry(UUID uuid, long requestedAccess, boolean grant, boolean isGroup) {
    AtomicBoolean updated = new AtomicBoolean(false);

    aclEntries.compute(
        uuid,
        (id, current) -> {
          long allow = 0L;
          long deny = 0L;
          boolean groupFlag = isGroup;

          if (current != null) {
            allow = current.getAllow();
            deny = current.getDeny();
            groupFlag = current.isGroup();
          }

          if (grant) {
            allow = allow | requestedAccess;
            deny = deny & ~requestedAccess;
          } else {
            allow = allow & ~requestedAccess;
            deny = deny | requestedAccess;
          }

          updated.set(true);

          if (allow == 0L && deny == 0L) {
            return null; // remove entry if no bits set
          }

          return new AclEntry(id, groupFlag, allow, deny);
        });

    return updated.get();
  }

  public boolean remove(UUID uuid, long requestedAccess) {
    AtomicBoolean changed = new AtomicBoolean(false);

    if (requestedAccess == -1L) {
      changed.set(aclEntries.remove(uuid) != null);
      return changed.get();
    }

    aclEntries.computeIfPresent(
        uuid,
        (id, current) -> {
          long newAllow = current.getAllow() & ~requestedAccess;
          long newDeny = current.getDeny() & ~requestedAccess;

          changed.set(true);

          if (newAllow == 0L && newDeny == 0L) {
            return null; // remove entry
          }

          return new AclEntry(id, current.isGroup(), newAllow, newDeny);
        });

    return changed.get();
  }

  public List<AclEntry> getAclEntries() {
    return new ArrayList<>(aclEntries.values());
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
      if ((aclEntry.getAllow() & requestedAccess) != 0L) {
        return Access.ALLOW;
      } else if ((aclEntry.getDeny() & requestedAccess) != 0L) {
        return Access.DENY;
      }
    }
    return Access.UNKNOWN;
  }

  private AclEntry find(UUID uuid) {
    return aclEntries.get(uuid);
  }
}
