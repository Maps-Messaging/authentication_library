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

import io.mapsmessaging.persistance.PersistentObject;
import io.mapsmessaging.security.identity.GroupEntry;
import io.mapsmessaging.security.identity.IdentityEntry;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.*;
import lombok.Getter;
import lombok.ToString;

@Getter
@ToString
public class Identity extends PersistentObject {

  private final UUID id;
  private final String username;
  private final Map<String, String> attributes;
  private final List<Group> groupList;

  public Identity(UUID id, IdentityEntry identityEntry, List<Group> groupList) {
    this.id = id;
    username = identityEntry.getUsername();
    this.groupList = groupList;
    attributes = buildAttributes(identityEntry);
  }

  public Identity(UUID id, String username, Map<String, String> attributes, List<Group> groupList) {
    this.id = id;
    this.username = username;
    this.attributes = attributes;
    this.groupList = groupList;
  }

  public Identity (InputStream inputStream) throws IOException {
    id = UUID.fromString(readString(inputStream));
    username = readString(inputStream);
    int attributeSize = readInt(inputStream);
    attributes = new HashMap<>();
    for(int i=0;i<attributeSize;i++){
      String key =  readString(inputStream);
      String value = readString(inputStream);
      attributes.put(key, value);
    }
    int groupCount = readInt(inputStream);
    groupList = new ArrayList<>();
    for(int i=0;i<groupCount;i++){
      groupList.add(readGroup(inputStream));
    }
  }

  public void saveIdentity(OutputStream outputStream) throws IOException {
    writeString(outputStream, getId().toString());
    writeString(outputStream, getUsername());
    if(getAttributes() != null && !getAttributes().isEmpty()){
      writeInt(outputStream, getAttributes().size());
      for(Map.Entry<String, String> attribute:getAttributes().entrySet()){
        writeString(outputStream, attribute.getKey());
        writeString(outputStream, attribute.getValue());
      }
    }
    else{
      writeInt(outputStream, 0);
    }
    if(getGroupList() != null && !getGroupList().isEmpty()){
      writeInt(outputStream, getGroupList().size());
      for(Group group:getGroupList()){
        saveGroup(outputStream, group);
      }
    }
    else{
      writeInt(outputStream, 0);
    }
  }

  private Map<String, String> buildAttributes(IdentityEntry identityEntry) {
    Map<String, String> map = new LinkedHashMap<>();
    identityEntry.setAttributeMap(map);
    return map;
  }

  private void saveGroup(OutputStream outputStream, Group group) throws IOException {
    writeString(outputStream, group.getId().toString());
    writeString(outputStream, group.getName());
  }

  private Group readGroup(InputStream inputStream) throws IOException {
    UUID id = UUID.fromString(readString(inputStream));
    String name = readString(inputStream);
    return new Group(id, new GroupEntry(name,new TreeSet<>() ));
  }


}
