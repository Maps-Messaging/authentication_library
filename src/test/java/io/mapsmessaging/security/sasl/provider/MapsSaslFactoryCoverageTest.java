/*
 * Copyright [ 2024 - 2026 ] MapsMessaging B.V.
 */
package io.mapsmessaging.security.sasl.provider;

import static org.junit.jupiter.api.Assertions.*;

import io.mapsmessaging.security.sasl.provider.plain.PlainSaslClient;
import io.mapsmessaging.security.sasl.provider.plain.PlainSaslServer;
import io.mapsmessaging.security.sasl.provider.scram.client.ScramSaslClient;
import io.mapsmessaging.security.sasl.provider.scram.server.ScramSaslServer;
import java.util.Map;
import javax.security.sasl.Sasl;
import org.junit.jupiter.api.Test;

class MapsSaslFactoryCoverageTest {

  @Test
  void serverFactoryCoversMechanismAndPolicyCombinations() throws Exception {
    MapsSaslServerFactory factory = new MapsSaslServerFactory();

    assertNull(factory.createSaslServer("PLAIN", "mqtt", "server", Map.of(), null));
    assertNull(factory.createSaslServer("UNKNOWN", "mqtt", "server", Map.of(), callbacks -> {}));

    assertInstanceOf(
        PlainSaslServer.class,
        factory.createSaslServer("PLAIN", "mqtt", "server", Map.of(), callbacks -> {}));
    assertInstanceOf(
        ScramSaslServer.class,
        factory.createSaslServer("SCRAM-SHA-256", "mqtt", "server", Map.of(), callbacks -> {}));

    assertArrayEquals(
        new String[]{"SCRAM-SHA-256", "PLAIN"},
        factory.getMechanismNames(null));
    assertArrayEquals(
        new String[]{"SCRAM-SHA-256"},
        factory.getMechanismNames(Map.of(Sasl.POLICY_NOPLAINTEXT, "true")));
    assertArrayEquals(
        new String[0],
        factory.getMechanismNames(Map.of(Sasl.QOP, "auth-int")));
    assertArrayEquals(
        new String[]{"SCRAM-SHA-256", "PLAIN"},
        factory.getMechanismNames(Map.of(Sasl.QOP, "auth-int, auth")));

    for (String property : new String[]{
        Sasl.POLICY_NODICTIONARY,
        Sasl.POLICY_FORWARD_SECRECY,
        Sasl.POLICY_PASS_CREDENTIALS}) {
      assertArrayEquals(
          new String[0],
          factory.getMechanismNames(Map.of(property, "true")));
    }

    assertArrayEquals(
        new String[]{"SCRAM-SHA-256"},
        factory.getMechanismNames(Map.of(Sasl.POLICY_NOACTIVE, "true")));
  }

  @Test
  void clientFactoryCoversNullUnknownAndPolicyPaths() throws Exception {
    MapsSaslClientFactory factory = new MapsSaslClientFactory();

    assertNull(factory.createSaslClient(null, null, "mqtt", "server", Map.of(), callbacks -> {}));
    assertNull(factory.createSaslClient(new String[]{"PLAIN"}, null, "mqtt", "server", Map.of(), null));
    assertNull(factory.createSaslClient(new String[]{"UNKNOWN"}, null, "mqtt", "server", Map.of(), callbacks -> {}));

    assertInstanceOf(
        PlainSaslClient.class,
        factory.createSaslClient(new String[]{"PLAIN"}, null, "mqtt", "server", Map.of(), callbacks -> {}));
    assertInstanceOf(
        ScramSaslClient.class,
        factory.createSaslClient(new String[]{"SCRAM-SHA-256"}, null, "mqtt", "server", Map.of(), callbacks -> {}));

    assertArrayEquals(
        new String[]{"SCRAM-SHA-256"},
        factory.getMechanismNames(Map.of(Sasl.POLICY_NOPLAINTEXT, "true")));
    assertArrayEquals(
        new String[0],
        factory.getMechanismNames(Map.of(Sasl.QOP, "auth-conf")));
  }
}
