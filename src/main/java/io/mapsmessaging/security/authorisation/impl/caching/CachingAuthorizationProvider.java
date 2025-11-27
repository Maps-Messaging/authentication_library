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

package io.mapsmessaging.security.authorisation.impl.caching;


import io.mapsmessaging.configuration.ConfigurationProperties;
import io.mapsmessaging.security.access.Group;
import io.mapsmessaging.security.access.Identity;
import io.mapsmessaging.security.authorisation.*;
import lombok.Getter;

import java.time.Duration;
import java.util.Collection;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicBoolean;

public class CachingAuthorizationProvider implements AuthorizationProvider {

  @Getter
  private final AuthorizationProvider delegate;
  private final Map<CacheKey, CacheEntry> cache;
  private final long ttlMillis;
  private final long refreshAheadMillis;
  private final ExecutorService executorService;

  public CachingAuthorizationProvider(AuthorizationProvider delegate,
                                      Duration ttl,
                                      Duration refreshAhead,
                                      ExecutorService executorService) {
    this.delegate = Objects.requireNonNull(delegate, "delegate");
    this.ttlMillis = (ttl != null ? ttl : Duration.ofSeconds(3)).toMillis();
    this.refreshAheadMillis = (refreshAhead != null ? refreshAhead : Duration.ofMillis(500)).toMillis();
    this.cache = new ConcurrentHashMap<>();
    this.executorService = (executorService != null
        ? executorService
        : Executors.newCachedThreadPool(r -> {
      Thread t = new Thread(r, "auth-cache-refresh");
      t.setDaemon(true);
      return t;
    }));
  }

  public CachingAuthorizationProvider(AuthorizationProvider delegate, Duration ttl, Duration refreshAhead) {
    this(delegate, ttl, refreshAhead, null);
  }

  public CachingAuthorizationProvider(AuthorizationProvider delegate, Duration ttl) {
    this(delegate, ttl, Duration.ofMillis(500), null);
  }

  @Override
  public String getName() {
    return "Caching";
  }

  @Override
  public void reset(){
    delegate.reset();
    cache.clear();
  }

  @Override
  public AuthorizationProvider create(ConfigurationProperties config, Permission[] permissions, ResourceTraversalFactory factory) {
    return null;
  }

  @Override
  public boolean canAccess(Identity identity,
                           Permission permission,
                           ProtectedResource protectedResource) {

    long now = System.currentTimeMillis();
    CacheKey cacheKey = new CacheKey(identity, permission, protectedResource);
    CacheEntry cacheEntry = cache.get(cacheKey);

    if (cacheEntry != null && now < cacheEntry.expiresAtMillis) {
      long refreshTriggerTime = cacheEntry.expiresAtMillis - refreshAheadMillis;
      if (refreshAheadMillis > 0 && now >= refreshTriggerTime &&
          cacheEntry.refreshInProgress.compareAndSet(false, true)) {
        refreshAsync(cacheKey, cacheEntry);
      }
      return cacheEntry.allowed;
    }

    boolean allowed = delegate.canAccess(identity, permission, protectedResource);
    CacheEntry newEntry = new CacheEntry(allowed, now + ttlMillis);
    cache.put(cacheKey, newEntry);
    return allowed;
  }

  @Override
  public void grantAccess(Grantee grantee,
                          Permission permission,
                          ProtectedResource protectedResource) {
    delegate.grantAccess(grantee, permission, protectedResource);
    cache.clear();
  }

  @Override
  public void denyAccess(
      Grantee grantee, Permission permission, ProtectedResource protectedResource) {
    delegate.denyAccess(grantee, permission, protectedResource);
    cache.clear();
  }

  @Override
  public void revokeAccess(Grantee grantee,
                           Permission permission,
                           ProtectedResource protectedResource) {
    delegate.revokeAccess(grantee, permission, protectedResource);
    cache.clear();
  }

  @Override
  public void registerIdentity(UUID identityId) {
    delegate.registerIdentity(identityId);
    cache.clear();
  }

  @Override
  public void deleteIdentity(UUID identityId) {
    delegate.deleteIdentity(identityId);
    cache.clear();
  }

  @Override
  public void registerGroup(UUID groupId) {
    delegate.registerGroup(groupId);
    cache.clear();
  }

  @Override
  public void deleteGroup(UUID groupId) {
    delegate.deleteGroup(groupId);
    cache.clear();
  }

  @Override
  public void addGroupMember(UUID groupId, UUID identityId) {
    delegate.addGroupMember(groupId, identityId);
    cache.clear();
  }

  @Override
  public void removeGroupMember(UUID groupId, UUID identityId) {
    delegate.removeGroupMember(groupId, identityId);
    cache.clear();
  }

  @Override
  public void registerResource(ProtectedResource protectedResource, ResourceCreationContext resourceCreationContext) {
    delegate.registerResource(protectedResource, resourceCreationContext);
  }

  @Override
  public void deleteResource(ProtectedResource protectedResource) {
    delegate.deleteResource(protectedResource);
  }

  @Override
  public Collection<Grant> getGrantsForIdentity(Identity identity) {
    return delegate.getGrantsForIdentity(identity);
  }

  @Override
  public Collection<Grant> getGrantsForGroup(Group group) {
    return delegate.getGrantsForGroup(group);
  }

  @Override
  public Collection<Grant> getGrantsForResource(ProtectedResource protectedResource) {
    return delegate.getGrantsForResource(protectedResource);
  }

  public void shutdown() {
    executorService.shutdown();
  }

  private void refreshAsync(CacheKey cacheKey, CacheEntry oldEntry) {
    executorService.submit(() -> {
      try {
        long now = System.currentTimeMillis();
        boolean allowed = delegate.canAccess(cacheKey.identity, cacheKey.permission, cacheKey.protectedResource);
        CacheEntry newEntry = new CacheEntry(allowed, now + ttlMillis);
        cache.put(cacheKey, newEntry);
      } finally {
        oldEntry.refreshInProgress.set(false);
      }
    });
  }

  private static final class CacheKey {

    private final Identity identity;
    private final Permission permission;
    private final ProtectedResource protectedResource;
    private final int hashCode;

    private CacheKey(Identity identity,
                     Permission permission,
                     ProtectedResource protectedResource) {
      this.identity = identity;
      this.permission = permission;
      this.protectedResource = protectedResource;
      this.hashCode = computeHashCode();
    }

    private int computeHashCode() {
      int result = 17;
      result = 31 * result + (identity != null ? identity.hashCode() : 0);
      result = 31 * result + (permission != null ? permission.getName().hashCode() : 0);
      result = 31 * result + (protectedResource != null ? protectedResource.hashCode() : 0);
      return result;
    }

    @Override
    public boolean equals(Object obj) {
      if (this == obj) {
        return true;
      }
      if (obj == null || getClass() != obj.getClass()) {
        return false;
      }
      CacheKey other = (CacheKey) obj;
      if (!Objects.equals(identity, other.identity)) {
        return false;
      }
      if (permission == null || other.permission == null) {
        return permission == other.permission;
      }
      if (!Objects.equals(permission.getName(), other.permission.getName())) {
        return false;
      }
      return Objects.equals(protectedResource, other.protectedResource);
    }

    @Override
    public int hashCode() {
      return hashCode;
    }
  }

  private static final class CacheEntry {
    private final boolean allowed;
    private final long expiresAtMillis;
    private final AtomicBoolean refreshInProgress = new AtomicBoolean(false);

    private CacheEntry(boolean allowed, long expiresAtMillis) {
      this.allowed = allowed;
      this.expiresAtMillis = expiresAtMillis;
    }
  }
}
