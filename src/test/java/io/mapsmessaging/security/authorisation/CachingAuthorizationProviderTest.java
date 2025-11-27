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

import io.mapsmessaging.security.authorisation.impl.caching.CachingAuthorizationProvider;
import io.mapsmessaging.security.authorisation.impl.openfga.OpenFGAAuthorizationProvider;
import org.junit.jupiter.api.Test;

class CachingAuthorizationProviderTest extends OpenFgaAuthorizationProviderTest {

  @Override
  protected AuthorizationProvider createAuthorizationProvider() throws Exception {
    return AuthTestHelper.createCachingAuthorizationProvider(null);
  }

  @Test
  void testPermissionIsolationForUser() {
    Grantee aliceGrantee = createGranteeForIdentity(identityAlice);

    authorizationProvider.grantAccess(aliceGrantee, TestPermissions.READ, protectedResource);

    long end = System.currentTimeMillis() + 10000;
    AuthorizationProvider delegate = ((CachingAuthorizationProvider)authorizationProvider).getDelegate();
    long startCount  =0;
    long endCount  =0;
    if(delegate instanceof OpenFGAAuthorizationProvider fgaAuthorizationProvider) {
      startCount = fgaAuthorizationProvider.getRequestCount();
    }
    while (System.currentTimeMillis() < end) {
      assertTrue(
          authorizationProvider.canAccess(identityAlice, TestPermissions.READ, protectedResource),
          "READ should be allowed after grant"
      );
      assertFalse(
          authorizationProvider.canAccess(identityAlice, TestPermissions.WRITE, protectedResource),
          "WRITE should not be allowed when only READ granted"
      );
      assertFalse(
          authorizationProvider.canAccess(identityAlice, TestPermissions.DELETE, protectedResource),
          "DELETE should not be allowed when only READ granted"
      );
      assertFalse(
          authorizationProvider.canAccess(identityAlice, TestPermissions.CREATE, protectedResource),
          "CREATE should not be allowed when only READ granted"
      );
    }
    if(delegate instanceof OpenFGAAuthorizationProvider fgaAuthorizationProvider) {
      endCount = fgaAuthorizationProvider.getRequestCount();
    }
    assertTrue((endCount - startCount < 10));
  }
}
