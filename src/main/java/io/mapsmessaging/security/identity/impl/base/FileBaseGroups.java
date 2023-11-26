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

package io.mapsmessaging.security.identity.impl.base;

import io.mapsmessaging.security.identity.GroupEntry;
import io.mapsmessaging.security.identity.IdentityEntry;
import io.mapsmessaging.security.identity.IllegalFormatException;
import io.mapsmessaging.security.identity.impl.apache.HtGroupEntry;

import java.io.IOException;
import java.util.LinkedHashMap;
import java.util.Map;

public abstract class FileBaseGroups extends FileLoader {

  private final Map<String, GroupEntry> groups;

  public FileBaseGroups(String filename) {
    super(filename);
    groups = new LinkedHashMap<>();
  }

  protected abstract String getDomain();

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

  public void addEntry(String groupName) throws IOException {
    GroupEntry groupEntry = new HtGroupEntry(groupName);
    groups.put(groupName, groupEntry);
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