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

package io.mapsmessaging.security.storage;

import java.io.IOException;
import java.util.Map;
import java.util.ServiceLoader;

@SuppressWarnings("java:S6548") // yes it is a singleton
public class StorageFactory {
  private static class Holder {
    static final StorageFactory INSTANCE = new StorageFactory();
  }

  public static StorageFactory getInstance() {
    return Holder.INSTANCE;
  }

  private final ServiceLoader<Store> storeTypes;


  private StorageFactory(){
    storeTypes =  ServiceLoader.load(Store.class);
  }

  public Store getStore(Map<String, Object> config) throws IOException {
    if (config.containsKey("store")) {
      String storename = (String) config.get("store");
      for (Store store : storeTypes) {
        if(store.getName().equalsIgnoreCase(storename)){
          return store.create(config);
        }
      }
    }
    return new FileStore();
  }
}
