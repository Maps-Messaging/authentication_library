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

package io.mapsmessaging.security.identity.impl.external;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.mapsmessaging.security.passwords.PasswordBuffer;
import org.junit.jupiter.api.Test;

class JwtPasswordHasherTest {

  @Test
  void rejectedAuthenticationCannotMatchEmptyStoredHash() throws Exception {
    TestJwtPasswordHasher hasher = new TestJwtPasswordHasher(false);

    assertFalse(hasher.matches("invalid-token".toCharArray()));
  }

  @Test
  void rejectionClearsPreviousSuccessfulAuthenticationState() throws Exception {
    TestJwtPasswordHasher hasher = new TestJwtPasswordHasher(true);
    assertTrue(hasher.matches("valid-token".toCharArray()));

    hasher.accept = false;

    assertFalse(hasher.matches("invalid-token".toCharArray()));
  }

  private static final class TestJwtPasswordHasher extends JwtPasswordHasher {

    private boolean accept;

    private TestJwtPasswordHasher(boolean accept) {
      this.accept = accept;
    }

    @Override
    public String getName() {
      return "test-jwt";
    }

    @Override
    public char[] transformPassword(char[] password, byte[] salt, int cost) {
      resetAuthenticationState();
      if (!accept) {
        return authenticationFailed();
      }
      computedPassword = new PasswordBuffer(password);
      return computedPassword.getHash();
    }
  }
}
