/*
 * Copyright [ 2024 - 2026 ] MapsMessaging B.V.
 */
package io.mapsmessaging.security.jaas;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

class AnonymousPrincipalCoverageTest {

  @Test
  void exposesNameAndReadableDescription() {
    AnonymousPrincipal principal = new AnonymousPrincipal("anonymous");

    assertEquals("anonymous", principal.getName());
    assertEquals("AnonymousPrincipal User:anonymous", principal.toString());
  }
}
