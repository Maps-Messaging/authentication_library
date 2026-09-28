/*
 * Copyright [ 2024 - 2026 ] MapsMessaging B.V.
 */
package io.mapsmessaging.security.sasl.provider.scram.client;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Map;
import org.junit.jupiter.api.Test;

class ScramSaslClientReliabilityTest {

  @Test
  void acceptsSupportedSha256Algorithm() {
    ScramSaslClient client = new ScramSaslClient(
        "SHA-256",
        null,
        "mqtt",
        "server",
        Map.of(),
        callbacks -> {});

    assertEquals("SCRAM-SHA-256", client.getMechanismName());
    assertTrue(client.hasInitialResponse());
  }

  @Test
  void rejectsUnsupportedAlgorithmBeforeMacSetup() {
    IllegalArgumentException exception = assertThrows(
        IllegalArgumentException.class,
        () -> new ScramSaslClient(
            "SHA-1",
            null,
            "mqtt",
            "server",
            Map.of(),
            callbacks -> {}));

    assertEquals(
        "Unsupported SCRAM algorithm: SHA-1",
        exception.getMessage());
  }
}
