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

package io.mapsmessaging.security.identity.impl.base;

import io.mapsmessaging.security.identity.GroupEntry;
import io.mapsmessaging.security.identity.IdentityEntry;
import io.mapsmessaging.security.identity.IllegalFormatException;
import io.mapsmessaging.security.identity.impl.apache.HtGroupEntry;
import java.io.IOException;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public abstract class FileBaseGroups extends FileLoader {

  private final Map<String, GroupEntry> groups;

  protected FileBaseGroups(String filename) {
    super(filename);
    groups = new LinkedHashMap<>();
  }

  protected abstract GroupEntry load(String line) throws IllegalFormatException;

  public void parse(String line) throws IllegalFormatException {
    GroupEntry group = load(line);
    groups.put(group.getName(), group);
  }

  public GroupEntry findGroup(String name) {
    return groups.get(name);
  }

  public void loadGroups(IdentityEntry identityEntry) {
    identityEntry.clearGroups();
    for (GroupEntry groupEntry : groups.values()) {
      if (groupEntry.isInGroup(identityEntry.getUsername())) {
        identityEntry.addGroup(groupEntry);
      }
    }
  }

  public List<GroupEntry> getGroups() {
    return List.copyOf(groups.values());
  }

  public void addEntry(String groupConfig) throws IOException {
    GroupEntry groupEntry = new HtGroupEntry(groupConfig);
    groups.put(groupEntry.getName(), groupEntry);
    add(groupEntry.toString());
  }

  public void deleteEntry(String groupName) throws IOException {
    GroupEntry entry = groups.get(groupName);
    if (entry != null) {
      groups.remove(groupName);
      delete(groupName);
    }

  }
}