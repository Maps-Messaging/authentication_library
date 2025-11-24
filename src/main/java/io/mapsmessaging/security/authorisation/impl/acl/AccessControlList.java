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
    return new AccessControlList( config);
  }

  public long getSubjectAccess(Identity identity) {
    long mask = 0;
    if (identity != null) {
      long time = System.currentTimeMillis();
      mask = processAclEntriesForSubject(identity.getId(), time);
      mask |= processGroups(identity.getGroupList(), time);
    }
    return mask;
  }

  public long getGroupAccess(Group group){
    long time = System.currentTimeMillis();
    return processGroups(List.of(group), time);
  }

  public long getRawAccess(UUID uuid){
    return processAclEntriesForSubject(uuid, System.currentTimeMillis());
  }

  private long processAclEntriesForSubject(UUID authId, long time) {
    return aclEntries.stream()
        .filter(aclEntry -> isValidAclEntry(aclEntry, time, authId))
        .mapToLong(AclEntry::getPermissions)
        .reduce(0, (a, b) -> a | b);
  }

  private long processGroups(List<Group> groups, long time) {
    return groups.stream()
        .mapToLong(groupIdMap -> processAclEntriesForGroupId(groupIdMap, time))
        .reduce(0, (a, b) -> a | b);
  }

  private long processAclEntriesForGroupId(Group group, long time) {
    return aclEntries.stream()
        .filter(aclEntry -> isValidAclEntry(aclEntry, time, group.getId()))
        .mapToLong(AclEntry::getPermissions)
        .reduce(0, (a, b) -> a | b);
  }

  private boolean isValidAclEntry(AclEntry aclEntry, long time, UUID authId) {
    return aclEntry.matches(authId);
  }

  // We are exiting early here because we want to fast exit once we found access is allowed
  @SuppressWarnings("java:S3516")
  public boolean canAccess(Identity identity, long requestedAccess) {
    if (identity == null || requestedAccess == 0) {
      return false;
    }

    UUID authId = identity.getId();
    if (checkAccessForId(authId, requestedAccess)) {
      return true;
    }

    if (!identity.getGroupList().isEmpty()) {
      for (Group group : identity.getGroupList()) {
        if (checkAccessForId(group.getId(), requestedAccess)) {
          return true;
        }
      }
    }
    return false;
  }

  public boolean addUser(UUID uuid, long requestedAccess) {
    AclEntry entry = new AclEntry(uuid, false, requestedAccess);
    aclEntries.add(entry);
    return true;
  }

  public boolean addGroup(UUID uuid, long requestedAccess) {
    AclEntry entry = new AclEntry(uuid, true, requestedAccess);
    aclEntries.add(entry);
    return true;
  }

  public boolean remove(UUID uuid, long requestedAccess) {
    aclEntries.removeIf(entry -> entry.matches(uuid) && entry.getPermissions() == requestedAccess);
    return true;
  }

  public List<AclEntry> getAclEntries() {
    return new ArrayList<>(aclEntries);
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