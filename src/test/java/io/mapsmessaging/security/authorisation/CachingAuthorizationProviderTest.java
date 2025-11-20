package io.mapsmessaging.security.authorisation;

import io.mapsmessaging.security.authorisation.impl.caching.CachingAuthorizationProvider;
import org.junit.jupiter.api.Test;

import java.time.Duration;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;


class CachingAuthorizationProviderTest extends OpenFgaAuthorizationProviderTest {

  @Override
  protected AuthorizationProvider createAuthorizationProvider() throws Exception {
    return new CachingAuthorizationProvider(super.createAuthorizationProvider(), Duration.ofSeconds(5));
  }

  @Test
  void testPermissionIsolationForUser() {
    Grantee aliceGrantee = createGranteeForIdentity(identityAlice);

    authorizationProvider.grantAccess(aliceGrantee, TestPermissions.READ, protectedResource);

    long end = System.currentTimeMillis() + 10000;
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
  }
}
