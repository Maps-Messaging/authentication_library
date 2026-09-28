/*
 * Copyright [ 2020 - 2024 ] Matthew Buckton
 *  Copyright [ 2024 - 2026 ] MapsMessaging B.V.
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
 */

package io.mapsmessaging.security.identity.principals;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import java.time.Instant;
import java.util.Date;
import org.junit.jupiter.api.Test;

class JwtPrincipalTest {

  private static final Algorithm ALGORITHM = Algorithm.HMAC256("test-key");

  @Test
  void currentTokenIsActiveAndNotExpired() {
    JwtPrincipal principal = createPrincipal(Instant.now().minusSeconds(60), Instant.now().plusSeconds(60));

    assertTrue(principal.isActive());
    assertFalse(principal.hasExpired());
  }

  @Test
  void expiredTokenIsNotActive() {
    JwtPrincipal principal = createPrincipal(Instant.now().minusSeconds(120), Instant.now().minusSeconds(60));

    assertFalse(principal.isActive());
    assertTrue(principal.hasExpired());
  }

  @Test
  void futureTokenIsNotActiveOrExpired() {
    JwtPrincipal principal = createPrincipal(Instant.now().plusSeconds(60), Instant.now().plusSeconds(120));

    assertFalse(principal.isActive());
    assertFalse(principal.hasExpired());
  }

  private JwtPrincipal createPrincipal(Instant issuedAt, Instant expiresAt) {
    String token =
        JWT.create()
            .withIssuedAt(Date.from(issuedAt))
            .withExpiresAt(Date.from(expiresAt))
            .sign(ALGORITHM);
    return new JwtPrincipal(JWT.decode(token));
  }
}
