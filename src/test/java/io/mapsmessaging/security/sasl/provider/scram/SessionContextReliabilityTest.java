/*
 * Copyright [ 2024 - 2026 ] MapsMessaging B.V.
 */
package io.mapsmessaging.security.sasl.provider.scram;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;

class SessionContextReliabilityTest {

  @Test
  void saltedPasswordCanBeGeneratedBeforeMacInitialisation() throws Exception {
    SessionContext context = new SessionContext();

    byte[] derived = context.generateSaltedPassword(
        "password".toCharArray(),
        "salt-value".getBytes(StandardCharsets.UTF_8),
        4096);

    assertEquals(32, derived.length);
  }

  @Test
  void resetPreservesValidScramKeySize() throws Exception {
    SessionContext context = new SessionContext();
    context.reset();

    byte[] derived = context.generateSaltedPassword(
        "password".getBytes(StandardCharsets.UTF_8),
        "salt-value".getBytes(StandardCharsets.UTF_8),
        4096);

    assertEquals(32, derived.length);
  }
}
