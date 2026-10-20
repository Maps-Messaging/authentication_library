/*
 * Copyright [ 2024 - 2026 ] MapsMessaging B.V.
 */
package io.mapsmessaging.security.sasl.provider.scram.server;

import static org.junit.jupiter.api.Assertions.*;

import java.util.Map;
import javax.security.sasl.Sasl;
import javax.security.sasl.SaslException;
import org.junit.jupiter.api.Test;

class ScramSaslServerCoverageTest {

  @Test
  void exposesMechanismAndRejectsUnsupportedAlgorithm() throws Exception {
    ScramSaslServer server =
        new ScramSaslServer("SHA-256", "mqtt", "server", Map.of(), callbacks -> {});
    assertEquals("SCRAM-SHA-256", server.getMechanismName());
    assertFalse(server.isComplete());

    assertThrows(IllegalStateException.class, server::getAuthorizationID);
    assertThrows(IllegalStateException.class, () -> server.getNegotiatedProperty(Sasl.QOP));

    server.dispose();
    assertThrows(SaslException.class, () -> server.evaluateResponse(new byte[0]));

    assertThrows(
        SaslException.class,
        () -> new ScramSaslServer("SHA-1", "mqtt", "server", Map.of(), callbacks -> {}));
  }
}
