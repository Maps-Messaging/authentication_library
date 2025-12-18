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

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.mapsmessaging.security.access.Identity;
import java.util.UUID;
import org.junit.jupiter.api.Test;

public abstract class AbstractNamespaceTraversalAuthorizationTest extends BaseSecurityTest {

  private Identity newIdentity() {
    return AuthTestHelper.createIdentity(UUID.randomUUID().toString());
  }

  private ProtectedResource topic(String tenant, String path) {
    return new ProtectedResource("resource", path, tenant);
  }

 public abstract AuthorizationProvider createProvider(ResourceTraversalFactory factory) throws Exception;

  @Test
  public void testGrantOnParentAllowsChildViaTraversal() throws Exception {
    ResourceTraversalFactory factory = new TestResourceTraversalFactory();
    AuthorizationProvider provider = createProvider(factory);

    Identity identity = newIdentity();

    ProtectedResource parent = topic("tenant1", "a/b/c");
    ProtectedResource child = topic("tenant1", "a/b/c/d/topic1");

    // grant only on parent
    provider.grant(identity  , TestPermissions.READ, parent);

    // child should be allowed via walking: child -> a/b/c/d -> a/b/c
    boolean canAccessChild = provider.canAccess(identity, TestPermissions.READ, child);
    assertTrue(canAccessChild, "Expected access via parent namespace grant");
  }

  @Test
  public void testNoGrantAnywhereDenies() throws Exception {
    ResourceTraversalFactory factory = new TestResourceTraversalFactory();
    AuthorizationProvider provider = createProvider(factory);

    Identity identity = newIdentity();
    ProtectedResource resource = topic("tenant1", "x/y/z/topic1");

    boolean canAccess = provider.canAccess(identity, TestPermissions.READ, resource);
    assertFalse(canAccess, "Expected default deny when no grants exist in namespace");
  }

  @Test
  public void testGrantOnRootDoesNotAffectOtherTenant() throws Exception {
    ResourceTraversalFactory factory = new TestResourceTraversalFactory();
    AuthorizationProvider provider = createProvider(factory);

    Identity identity = newIdentity();

    ProtectedResource rootTenant1 = topic("tenant1", "");
    ProtectedResource resourceTenant2 = topic("tenant2", "a/b/c/topic1");

    provider.grant(identity, TestPermissions.READ, rootTenant1);

    boolean canAccessTenant2 = provider.canAccess(identity, TestPermissions.READ, resourceTenant2);
    assertFalse(canAccessTenant2, "Tenant isolation should prevent cross-tenant grants");
  }
}
