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

package io.mapsmessaging.security.identity;

import static io.mapsmessaging.security.logging.AuthLogMessages.IDENTITY_LOOKUP_LOADED;

import io.mapsmessaging.logging.Logger;
import io.mapsmessaging.logging.LoggerFactory;
import java.util.Map;
import java.util.ServiceLoader;
import java.util.concurrent.ConcurrentHashMap;

public class IdentityLookupFactory {

  private static final IdentityLookupFactory instance = new IdentityLookupFactory();

  private final Map<String, IdentityLookup> identityLookupMap = new ConcurrentHashMap<>();

  private final ServiceLoader<IdentityLookup> identityLookups;
  private final Logger logger = LoggerFactory.getLogger(IdentityLookupFactory.class);

  public static IdentityLookupFactory getInstance() {
    return instance;
  }

  private IdentityLookupFactory() {
    identityLookups = ServiceLoader.load(IdentityLookup.class);
    for (IdentityLookup identityLookup : identityLookups) {
      logger.log(IDENTITY_LOOKUP_LOADED, identityLookup.getName());
    }
  }

  public void registerSiteIdentityLookup(String name, IdentityLookup identityLookup) {
    identityLookupMap.put(name, identityLookup);
  }

  public IdentityLookup getSiteWide(String name) {
    return identityLookupMap.get(name);
  }

  public IdentityLookup get(String name, Map<String, ?> config) {
    for (IdentityLookup identityLookup : identityLookups) {
      if (identityLookup.getName().equalsIgnoreCase(name)) {
        return identityLookup.create(config);
      }
    }
    return null;
  }

}
