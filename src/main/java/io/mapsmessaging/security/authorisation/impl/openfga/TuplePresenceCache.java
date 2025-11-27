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

package io.mapsmessaging.security.authorisation.impl.openfga;

import dev.openfga.sdk.api.client.OpenFgaClient;
import dev.openfga.sdk.api.client.model.ClientReadRequest;
import dev.openfga.sdk.api.client.model.ClientReadResponse;
import dev.openfga.sdk.api.configuration.ClientReadOptions;
import dev.openfga.sdk.errors.FgaInvalidParameterException;
import io.mapsmessaging.security.access.Group;
import io.mapsmessaging.security.access.Identity;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.*;

public class TuplePresenceCache {

  private static final class CacheEntry {
    final boolean value;
    final long expiryMillis;

    CacheEntry(boolean value, long expiryMillis) {
      this.value = value;
      this.expiryMillis = expiryMillis;
    }

    boolean isExpired(long now) {
      return now >= expiryMillis;
    }
  }

  private final OpenFgaClient openFgaClient;
  private final String userType;
  private final String groupType;
  private final String groupMemberRelation;
  private final long ttlMillis;

  private final Map<String, CacheEntry> cache = new ConcurrentHashMap<>();

  public TuplePresenceCache(OpenFgaClient openFgaClient,
                            String userType,
                            String groupType,
                            String groupMemberRelation,
                            long ttlMillis) {
    this.openFgaClient = openFgaClient;
    this.userType = userType;
    this.groupType = groupType;
    this.groupMemberRelation = groupMemberRelation;
    this.ttlMillis = ttlMillis;
  }

  public boolean hasAnyTuplesForIdentityOnObject(Identity identity, String object) {
    if (identity == null || object == null || object.isEmpty()) {
      return false;
    }

    String cacheKey = buildCacheKey(identity.getId(), object);
    long now = System.currentTimeMillis();

    CacheEntry cached = cache.get(cacheKey);
    if (cached != null && !cached.isExpired(now)) {
      return cached.value;
    }

    boolean result = fetchTuplePresence(identity, object);

    cache.put(cacheKey, new CacheEntry(result, now + ttlMillis));
    return result;
  }

  private String buildCacheKey(UUID identityId, String object) {
    return identityId.toString() + "|" + object;
  }

  private boolean fetchTuplePresence(Identity identity, String object) {
    List<String> principals = buildPrincipals(identity);

    for (String principal : principals) {
      ClientReadRequest request = new ClientReadRequest()
          .user(principal)
          ._object(object);

      ClientReadOptions options = new ClientReadOptions();
      try {
        ClientReadResponse response = openFgaClient.read(request, options).get();
        if (response.getTuples() != null && !response.getTuples().isEmpty()) {
          // Any tuple for this principal on this object is enough
          return true;
        }
      } catch (InterruptedException interruptedException) {
        Thread.currentThread().interrupt();
        return false;
      } catch (ExecutionException | FgaInvalidParameterException executionException) {
        // safest behaviour is to treat errors as "no tuples", i.e. UNKNOWN → fall back to parent
        return false;
      }
    }

    return false;
  }

  private List<String> buildPrincipals(Identity identity) {
    List<String> principals = new ArrayList<>();

    // direct user principal
    principals.add(userType + ":" + identity.getId());

    // group principals (group:<id>#member)
    Collection<Group> groups = identity.getGroupList();
    if (groups != null) {
      for (Group group : groups) {
        principals.add(groupType + ":" + group.getId() + "#" + groupMemberRelation);
      }
    }

    return principals;
  }
}
