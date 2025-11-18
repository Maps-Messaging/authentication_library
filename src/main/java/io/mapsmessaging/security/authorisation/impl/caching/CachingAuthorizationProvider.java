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


import io.mapsmessaging.security.access.Group;
import io.mapsmessaging.security.access.Identity;
import io.mapsmessaging.security.authorisation.AuthorizationProvider;
import io.mapsmessaging.security.authorisation.Grantee;
import io.mapsmessaging.security.authorisation.Permission;
import io.mapsmessaging.security.authorisation.ProtectedResource;
import java.time.Duration;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;

public class CachingAuthorizationProvider implements AuthorizationProvider {

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
  public void revokeAccess(Grantee grantee,
                           Permission permission,
                           ProtectedResource protectedResource) {
    delegate.revokeAccess(grantee, permission, protectedResource);
    cache.clear();
  }

  public void registerIdentity(Identity identity) {
    delegate.registerIdentity(identity);
    cache.clear();
  }

  public void deleteIdentity(Identity identity) {
    delegate.deleteIdentity(identity);
    cache.clear();
  }

  public void registerGroup(Group group) {
    delegate.registerGroup(group);
    cache.clear();
  }

  public void deleteGroup(Group group) {
    delegate.deleteGroup(group);
    cache.clear();
  }

  public void addGroupMember(Group group, Identity identity) {
    delegate.addGroupMember(group, identity);
    cache.clear();
  }

  public void removeGroupMember(Group group, Identity identity) {
    delegate.removeGroupMember(group, identity);
    cache.clear();
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
