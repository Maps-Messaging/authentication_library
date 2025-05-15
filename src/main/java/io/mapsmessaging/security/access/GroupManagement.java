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

package io.mapsmessaging.security.access;

import io.mapsmessaging.security.access.mapping.GroupIdMap;
import io.mapsmessaging.security.access.mapping.GroupMapManagement;
import io.mapsmessaging.security.identity.GroupEntry;
import io.mapsmessaging.security.identity.IdentityEntry;
import io.mapsmessaging.security.identity.IdentityLookup;
import io.mapsmessaging.security.identity.principals.GroupIdPrincipal;
import io.mapsmessaging.security.uuid.UuidGenerator;
import java.io.IOException;
import java.security.Principal;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import javax.security.auth.Subject;

public class GroupManagement {

  private final IdentityLookup identityLookup;
  private final GroupMapManagement groupMapManagement;

  public GroupManagement(final IdentityLookup identityLookup, final GroupMapManagement groupMapManagement) {
    this.identityLookup = identityLookup;
    this.groupMapManagement = groupMapManagement;
  }

  protected Subject updateSubject(Subject subject, IdentityEntry identityEntry) {
    List<GroupIdMap> groups = new ArrayList<>();
    for (GroupEntry groupEntry : identityEntry.getGroups()) {
      String gKey = identityLookup.getDomain() + ":" + groupEntry.getName();
      GroupIdMap groupIdMap = groupMapManagement.get(gKey);
      if (groupIdMap != null) {
        groups.add(groupIdMap);
      }
    }
    Set<Principal> principalSet = subject.getPrincipals();
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

  public Group getGroup(String groupName) {
    GroupEntry entry = identityLookup.findGroup(groupName);
    if (entry != null) {
      return buildGroup(entry);
    }
    return null;
  }


  public List<Group> getAllGroups() {
    List<Group> list = new ArrayList<>();
    for (GroupEntry entry : identityLookup.getGroups()) {
      list.add(buildGroup(entry));
    }
    return list;
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

  public void mapUserToAllGroups(IdentityEntry entry){
    for (GroupEntry group : entry.getGroups()) {
      if (groupMapManagement.get(group.getName()) == null) {
        GroupIdMap groupIdMap = new GroupIdMap(UuidGenerator.getInstance().generate(), group.getName(), identityLookup.getDomain());
        groupMapManagement.add(groupIdMap);
      }
    }

  }
  public void deleteUserFromAllGroups(String username) throws IOException {
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
  }

  private Group buildGroup(GroupEntry entry){
    if (entry != null ) {
      GroupIdMap idMap = getGroupIdMap(entry.getName());
      if(idMap == null){
        idMap = mapGroup(entry.getName());
      }
      return new Group(idMap.getAuthId(), entry);
    }
    return null;
  }

  private GroupIdMap getGroupIdMap(String groupName) {
    return groupMapManagement.get(identityLookup.getDomain() + ":" + groupName);
  }


  private GroupIdMap mapGroup(String groupName){
    GroupIdMap groupIdMap = new GroupIdMap(UuidGenerator.getInstance().generate(), groupName, identityLookup.getDomain());
    groupMapManagement.add(groupIdMap);
    groupMapManagement.save();
    return groupIdMap;
  }

  public List<Group> getGroups(List<GroupEntry> groups) {
    List<Group> response = new ArrayList<>();
    for(GroupEntry entry:groups){
      response.add(buildGroup(entry));
    }
    return response;
  }
}
