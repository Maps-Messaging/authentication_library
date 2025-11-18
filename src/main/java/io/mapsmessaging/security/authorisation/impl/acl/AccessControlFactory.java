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


import java.util.List;
import java.util.ServiceLoader;

@SuppressWarnings("java:S6548") // yes it is a singleton
public class AccessControlFactory {

  private static class Holder {
    static final AccessControlFactory INSTANCE = new AccessControlFactory();
  }

  public static AccessControlFactory getInstance() {
    return Holder.INSTANCE;
  }

  private final ServiceLoader<AccessControlList> accessControlLists;

  private AccessControlFactory() {
    accessControlLists = ServiceLoader.load(AccessControlList.class);
  }

  public AccessControlList get(String name, List<String> config) {
    for (AccessControlList accessControlList : accessControlLists) {
      if (accessControlList.getName().equalsIgnoreCase(name)) {
        return accessControlList.create(config);
      }
    }
    return null;
  }

}
