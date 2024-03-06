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

package io.mapsmessaging.security.access.mapping;

import io.mapsmessaging.security.access.mapping.store.MapStore;
import java.io.*;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

public class MapManagement<T extends IdMap> {
  private final MapParser<T> parser;
  private final MapStore<T> store;
  private final Map<UUID, T> userIdMapByUuid;
  private final Map<String, T> userIdMapByUser;
  private boolean hasChanged;

  public MapManagement(MapStore<T> store, MapParser<T> parser) {
    userIdMapByUuid = new ConcurrentHashMap<>();
    userIdMapByUser = new ConcurrentHashMap<>();
    this.store = store;
    this.parser = parser;
    load();
    hasChanged = false;
  }

  public void clearAll() {
    userIdMapByUuid.clear();
    userIdMapByUser.clear();
    hasChanged = true;
  }

  public List<T> getAll() {
    return new ArrayList<>(userIdMapByUuid.values());
  }

  public T get(UUID uuid) {
    return userIdMapByUuid.get(uuid);
  }

  public T get(String username) {
    return userIdMapByUser.get(username);
  }

  public boolean delete(String name) {
    T entry = userIdMapByUser.remove(name);
    if (entry != null) {
      userIdMapByUuid.remove(entry.getAuthId());
      hasChanged = true;
      return true;
    }
    return false;
  }

  public boolean add(T entry) {
    if (!userIdMapByUser.containsKey(entry.getKey())) {
      userIdMapByUser.put(entry.getKey(), entry);
      userIdMapByUuid.put(entry.getAuthId(), entry);
      hasChanged = true;
      return true;
    }
    return false;
  }

  public void load() {
    List<T> loaded = store.load(parser);
    for (T entry : loaded) {
      userIdMapByUuid.put(entry.getAuthId(), entry);
      userIdMapByUser.put(entry.getKey(), entry);
    }
  }

  public void save() {
    if (hasChanged) {
      store.save(new ArrayList<>(userIdMapByUuid.values()), parser);
      hasChanged = false;
    }
  }

  public int size() {
    return userIdMapByUser.size();
  }

}
