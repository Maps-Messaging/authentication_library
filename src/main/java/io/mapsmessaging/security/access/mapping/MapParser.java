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

package io.mapsmessaging.security.access.mapping;

import java.util.ArrayList;
import java.util.List;

public abstract class MapParser<T extends IdMap> {

  /**
   * Creates a User to authId mapping based on the provided list.
   *
   * @param mapping the list of user to UUID mappings entries in the format "uuid = user identifier"
   * @return the created AccessControlList object
   */
  public List<T> createList(List<String> mapping) {
    List<T> userMap = new ArrayList<>();
    for (String mapEntry : mapping) {
      T entry = parse(mapEntry);
      if (entry != null) {
        userMap.add(entry);
      }
    }
    return userMap;
  }

  public List<String> writeToList(List<T> mapping) {
    List<String> dump = new ArrayList<>();
    for (T entry : mapping) {
      dump.add(entry.getAuthId().toString() + " = " + entry.getKey());
    }
    return dump;
  }

  public T parse(String aclEntry) {
    return createMapping(aclEntry);
  }

  protected abstract T createMapping(String identifier);
}
