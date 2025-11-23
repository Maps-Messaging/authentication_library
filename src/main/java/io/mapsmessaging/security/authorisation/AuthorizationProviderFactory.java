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
    if(name.equalsIgnoreCase("caching")){
      name = ""; // can not use caching as the base provider
    }
    for (AuthorizationProvider authorizationProvider : authorizationProviders) {
      if (authorizationProvider.getName().equalsIgnoreCase(name)) {
        ConfigurationProperties props = new ConfigurationProperties(config);
        AuthorizationProvider provider = authorizationProvider.create(props, permissions);
        if(props.getBooleanProperty("enableCaching", true)){
          long cacheTime = props.getLongProperty("cachingTime", 10);
          return new CachingAuthorizationProvider(provider, Duration.ofSeconds(cacheTime));
        }
        return provider;
      }
    }
    return null;
  }
}
