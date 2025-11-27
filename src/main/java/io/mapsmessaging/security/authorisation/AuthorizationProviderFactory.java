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

package io.mapsmessaging.security.authorisation;

import io.mapsmessaging.configuration.ConfigurationProperties;
import io.mapsmessaging.logging.Logger;
import io.mapsmessaging.logging.LoggerFactory;
import io.mapsmessaging.security.authorisation.impl.caching.CachingAuthorizationProvider;
import io.mapsmessaging.security.identity.IdentityLookupFactory;

import java.io.IOException;
import java.time.Duration;
import java.util.Map;
import java.util.ServiceLoader;

import static io.mapsmessaging.security.logging.AuthLogMessages.IDENTITY_LOOKUP_LOADED;

public class AuthorizationProviderFactory {

  private static class Holder {
    static final AuthorizationProviderFactory INSTANCE = new AuthorizationProviderFactory();
  }

  public static AuthorizationProviderFactory getInstance() {
    return Holder.INSTANCE;
  }

  private final ServiceLoader<AuthorizationProvider> authorizationProviders;

  private AuthorizationProviderFactory() {
    Logger logger = LoggerFactory.getLogger(IdentityLookupFactory.class);
    authorizationProviders = ServiceLoader.load(AuthorizationProvider.class);
    for (AuthorizationProvider authLookup : authorizationProviders) {
      logger.log(IDENTITY_LOOKUP_LOADED, authLookup.getName());
    }
  }

  public AuthorizationProvider get(String name, Map<String, Object> config, Permission[]  permissions) throws IOException {
    return get(name, config, permissions, null);
  }

  public AuthorizationProvider get(String name, Map<String, Object> config, Permission[]  permissions, ResourceTraversalFactory factory) throws IOException {
    if(factory == null) {
      factory = new DefaultFactory();
    }
    ConfigurationProperties props = new ConfigurationProperties(config);
    ConfigurationProperties authorisationConfig = (ConfigurationProperties) props.get("authorisation");

    if(name.equalsIgnoreCase("caching")){
      name = ""; // can not use caching as the base provider
    }
    for (AuthorizationProvider authorizationProvider : authorizationProviders) {
      if (authorizationProvider.getName().equalsIgnoreCase(name)) {
        AuthorizationProvider provider = authorizationProvider.create(props, permissions, factory);
        if(authorisationConfig != null &&  authorisationConfig.getBooleanProperty("enableCaching", true)){
          long cacheTime = authorisationConfig.getLongProperty("cachingTime", 10);
          return new CachingAuthorizationProvider(provider, Duration.ofSeconds(cacheTime));
        }
        return provider;
      }
    }
    return null;
  }

  private static final class DefaultFactory implements ResourceTraversalFactory {
    @Override
    public ResourceTraversal create(ProtectedResource resource) {
      return ResourceTraversalFactory.super.create(resource);
    }
  }

}
