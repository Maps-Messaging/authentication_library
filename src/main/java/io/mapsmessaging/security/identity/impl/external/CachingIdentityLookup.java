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

package io.mapsmessaging.security.identity.impl.external;

import io.mapsmessaging.security.identity.GroupEntry;
import io.mapsmessaging.security.identity.IdentityEntry;
import io.mapsmessaging.security.identity.IdentityLookup;
import java.io.IOException;
import java.util.*;

public abstract class CachingIdentityLookup<T extends IdentityEntry> implements IdentityLookup {

  protected final Map<String, GroupEntry> groupEntryMap = new LinkedHashMap<>();
  protected final Map<String, T> identityEntryMap = new LinkedHashMap<>();
  protected final List<T> identityEntries = new ArrayList<>();

  @Override
  public void updateGroup(GroupEntry groupEntry) throws IOException {
    IdentityLookup.super.updateGroup(groupEntry);
  }

  @Override
  public IdentityEntry findEntry(String username) {
    loadUsers();
    IdentityEntry identityEntry = identityEntryMap.get(username);
    if (identityEntry == null) {
      identityEntry = createIdentityEntry(username);
    }
    return identityEntry;
  }

  public void authorised(T identityEntry) {
    boolean added = false;
    if (!identityEntries.contains(identityEntry)) {
      identityEntries.add(identityEntry);
      added = true;
    }
    if (identityEntryMap.containsKey(identityEntry.getUsername())) {
      identityEntryMap.put(identityEntry.getUsername(), identityEntry);
      added = true;
    }
    if (added) {
      loadGroups(identityEntry);
    }
  }

  protected abstract void loadGroups(T identityEntry);

  protected abstract IdentityEntry createIdentityEntry(String username);

  protected abstract void loadUsers();

  @Override
  public boolean canManage(){
    return true;
  }
}
