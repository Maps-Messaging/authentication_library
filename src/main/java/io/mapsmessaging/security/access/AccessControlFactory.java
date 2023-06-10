/*
 * Copyright [ 2020 - 2023 ] [Matthew Buckton]
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package io.mapsmessaging.security.access;

import io.mapsmessaging.logging.Logger;
import io.mapsmessaging.logging.LoggerFactory;
import java.util.List;
import java.util.ServiceLoader;

public class AccessControlFactory {


  private static final AccessControlFactory instance = new AccessControlFactory();
  private final ServiceLoader<AccessControlList> accessControlLists;

  private final Logger logger = LoggerFactory.getLogger(AccessControlFactory.class);

  private AccessControlFactory() {
    accessControlLists = ServiceLoader.load(AccessControlList.class);
  }

  public static AccessControlFactory getInstance() {
    return instance;
  }

  public AccessControlList get(String name, AccessControlMapping accessControlMapping, List<String> config) {
    for (AccessControlList accessControlList : accessControlLists) {
      if (accessControlList.getName().equalsIgnoreCase(name)) {
        return accessControlList.create(accessControlMapping, config);
      }
    }
    return null;
  }

}
