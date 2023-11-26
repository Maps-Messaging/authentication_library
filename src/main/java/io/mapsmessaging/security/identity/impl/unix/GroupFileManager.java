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

package io.mapsmessaging.security.identity.impl.unix;

import io.mapsmessaging.security.identity.GroupEntry;
import io.mapsmessaging.security.identity.IdentityEntry;
import io.mapsmessaging.security.identity.IllegalFormatException;
import io.mapsmessaging.security.identity.impl.base.FileBaseGroups;

import java.util.LinkedHashMap;
import java.util.Map;

public class GroupFileManager extends FileBaseGroups {

  private final Map<Integer, GroupEntry> byId = new LinkedHashMap<>();

  public GroupFileManager(String filename) {
    super(filename);
    load();
  }

  @Override
  protected String getDomain() {
    return "unix";
  }

  @Override
  protected GroupEntry load(String line) throws IllegalFormatException {
    GroupFileEntry entry = new GroupFileEntry(line);
    byId.put(entry.getGroupId(), entry);
    return entry;
  }

  public GroupEntry findGroup(int id) {
    return byId.get(id);
  }

  public void loadGroups(IdentityEntry identityEntry) {
    for (GroupEntry groupEntry : byId.values()) {
      if (groupEntry.isInGroup(identityEntry.getUsername())) {
        identityEntry.addGroup(groupEntry);
      }
    }
  }
}