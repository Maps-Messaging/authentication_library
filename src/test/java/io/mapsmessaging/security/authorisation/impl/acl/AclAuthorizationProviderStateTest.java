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


import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

import io.mapsmessaging.security.access.Identity;
import io.mapsmessaging.security.authorisation.*;
import java.util.Collection;
import org.junit.jupiter.api.Test;

class AclAuthorizationProviderStateTest {

  private static class SimplePermission implements Permission {

    private final String name;

    private final long mask;

    private final String description;

    SimplePermission(String name, long mask, String description) {
      this.name = name;
      this.mask = mask;
      this.description = description;
    }

    @Override
    public String getName() {
      return name;
    }

    @Override
    public String getDescription() {
      return description;
    }

    @Override
    public long getMask() {
      return mask;
    }
  }

  private Permission[] createTestPermissions() {
    return new Permission[] {
        new SimplePermission("read", 1L << 0, "read permission"),
        new SimplePermission("write", 1L << 1, "write permission")
    };
  }

  @Test
  void testConstructorWithNonJsonStateDoesNotThrowAndResultsInNoGrants() {
    String nonJsonState = "this-is-not-json";

    Permission[] permissions = createTestPermissions();

    AclSaveState dummySaveState = null;
    ResourceTraversalFactory dummyFactory = new ResourceTraversalFactory() {
      @Override
      public ResourceTraversal create(ProtectedResource protectedResource) {
        return new ResourceTraversal() {
          @Override
          public boolean hasMore() {
            return false;
          }

          @Override
          public ProtectedResource current() {
            return protectedResource;
          }

          @Override
          public void moveToParent() {
          }
        };
      }
    };

    AclAuthorizationProvider provider = assertDoesNotThrow(
        () -> new AclAuthorizationProvider(nonJsonState, permissions, dummySaveState, dummyFactory),
        "Provider construction with non-JSON state should not throw"
    );

    Identity identity = AuthTestHelper.createIdentity("user-1");

    ProtectedResource protectedResource = new ProtectedResource("resource", "resource-1", "");

    Collection<Grant> grants = provider.getGrantsForIdentity(identity);
    assertEquals(0, grants.size(), "Non-JSON state should result in no grants being loaded");

    boolean canAccess =
        provider.canAccess(identity, permissions[0], protectedResource);
    assertFalse(canAccess, "With no grants loaded, access should be denied by default");
  }

  @Test
  void testConstructorWithEmptyStateDoesNotThrowAndResultsInNoGrants() {
    String emptyState = "";

    Permission[] permissions = createTestPermissions();

    AclSaveState dummySaveState = null;
    ResourceTraversalFactory dummyFactory = new ResourceTraversalFactory() {
      @Override
      public ResourceTraversal create(ProtectedResource protectedResource) {
        return new ResourceTraversal() {
          @Override
          public boolean hasMore() {
            return false;
          }

          @Override
          public ProtectedResource current() {
            return protectedResource;
          }

          @Override
          public void moveToParent() {
          }
        };
      }
    };

    AclAuthorizationProvider provider = assertDoesNotThrow(
        () -> new AclAuthorizationProvider(emptyState, permissions, dummySaveState, dummyFactory),
        "Provider construction with empty state should not throw"
    );

    Identity identity = AuthTestHelper.createIdentity("user-1");

    ProtectedResource protectedResource = new ProtectedResource("resource", "resource-1", "");

    Collection<Grant> grants = provider.getGrantsForIdentity(identity);
    assertEquals(0, grants.size(), "Empty state should result in no grants being loaded");

    boolean canAccess =
        provider.canAccess(identity, permissions[0], protectedResource);
    assertFalse(canAccess, "With no grants loaded, access should be denied by default");
  }
}
