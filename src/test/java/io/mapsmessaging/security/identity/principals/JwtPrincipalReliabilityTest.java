/*
 * Copyright [ 2024 - 2026 ] MapsMessaging B.V.
 */
package io.mapsmessaging.security.identity.principals;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import java.time.Instant;
import java.util.Date;
import org.junit.jupiter.api.Test;

class JwtPrincipalReliabilityTest {

  private static final Algorithm ALGORITHM = Algorithm.HMAC256("test-secret");

  @Test
  void activeTokenUsesConsistentExplicitTimeZone() {
    Instant now = Instant.now();
    String token = JWT.create()
        .withIssuedAt(Date.from(now.minusSeconds(60)))
        .withExpiresAt(Date.from(now.plusSeconds(60)))
        .sign(ALGORITHM);

    JwtPrincipal principal = new JwtPrincipal(JWT.decode(token));

    assertTrue(principal.isActive());
    assertFalse(principal.hasExpired());
  }

  @Test
  void expiredTokenIsInactive() {
    Instant now = Instant.now();
    String token = JWT.create()
        .withIssuedAt(Date.from(now.minusSeconds(120)))
        .withExpiresAt(Date.from(now.minusSeconds(60)))
        .sign(ALGORITHM);

    JwtPrincipal principal = new JwtPrincipal(JWT.decode(token));

    assertFalse(principal.isActive());
    assertTrue(principal.hasExpired());
  }
}
