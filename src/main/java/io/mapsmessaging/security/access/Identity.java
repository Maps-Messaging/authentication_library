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

import io.mapsmessaging.security.identity.IdentityEntry;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import lombok.Getter;
import lombok.ToString;

@Getter
@ToString
public class Identity {

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

  private Map<String, String> buildAttributes(IdentityEntry identityEntry) {
    Map<String, String> map = new LinkedHashMap<>();
    identityEntry.setAttributeMap(map);
    return map;
  }

}
