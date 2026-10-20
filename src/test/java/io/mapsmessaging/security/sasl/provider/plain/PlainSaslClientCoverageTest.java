/*
 * Copyright [ 2024 - 2026 ] MapsMessaging B.V.
 */
package io.mapsmessaging.security.sasl.provider.plain;

import static org.junit.jupiter.api.Assertions.*;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.sasl.Sasl;
import javax.security.sasl.SaslException;
import org.junit.jupiter.api.Test;

class PlainSaslClientCoverageTest {

  @Test
  void buildsInitialResponseAndCompletes() throws Exception {
    PlainSaslClient client = new PlainSaslClient(
        "authz",
        callbacks -> populate(callbacks, "alice", "secret".toCharArray()));

    assertEquals("PLAIN", client.getMechanismName());
    assertTrue(client.hasInitialResponse());
    assertFalse(client.isComplete());

    byte[] response = client.evaluateChallenge(new byte[0]);
    assertEquals(
        "authz\0alice\0secret",
        new String(response, StandardCharsets.UTF_8));
    assertTrue(client.isComplete());
    assertEquals("auth", client.getNegotiatedProperty(Sasl.QOP));
    assertNull(client.getNegotiatedProperty("other"));

    assertThrows(SaslException.class, () -> client.evaluateChallenge(new byte[0]));
    assertThrows(IllegalStateException.class, () -> client.wrap(new byte[1], 0, 1));
    assertThrows(IllegalStateException.class, () -> client.unwrap(new byte[1], 0, 1));

    client.dispose();
    assertFalse(client.isComplete());
  }

  @Test
  void rejectsInvalidChallengesAndCredentials() throws Exception {
    PlainSaslClient client = new PlainSaslClient(
        callbacks -> populate(callbacks, "alice", "secret".toCharArray()));
    assertThrows(SaslException.class, () -> client.evaluateChallenge(new byte[]{1}));

    PlainSaslClient missingUser = new PlainSaslClient(
        callbacks -> populate(callbacks, null, "secret".toCharArray()));
    assertThrows(SaslException.class, () -> missingUser.evaluateChallenge(new byte[0]));

    PlainSaslClient emptyPassword = new PlainSaslClient(
        callbacks -> populate(callbacks, "alice", new char[0]));
    assertThrows(SaslException.class, () -> emptyPassword.evaluateChallenge(new byte[0]));

    PlainSaslClient nulUser = new PlainSaslClient(
        callbacks -> populate(callbacks, "ali\0ce", "secret".toCharArray()));
    assertThrows(SaslException.class, () -> nulUser.evaluateChallenge(new byte[0]));

    PlainSaslClient nulPassword = new PlainSaslClient(
        callbacks -> populate(callbacks, "alice", new char[]{'a', '\0', 'b'}));
    assertThrows(SaslException.class, () -> nulPassword.evaluateChallenge(new byte[0]));

    PlainSaslClient badAuthz = new PlainSaslClient(
        "bad\0authz",
        callbacks -> populate(callbacks, "alice", "secret".toCharArray()));
    assertThrows(SaslException.class, () -> badAuthz.evaluateChallenge(new byte[0]));
  }

  @Test
  void wrapsCallbackFailureAndRejectsOversizedResponse() {
    PlainSaslClient callbackFailure =
        new PlainSaslClient(callbacks -> { throw new IOException("boom"); });
    SaslException failure =
        assertThrows(SaslException.class, () -> callbackFailure.evaluateChallenge(new byte[0]));
    assertInstanceOf(IOException.class, failure.getCause());

    char[] huge = new char[17_000];
    java.util.Arrays.fill(huge, 'x');
    PlainSaslClient oversized =
        new PlainSaslClient(callbacks -> populate(callbacks, "alice", huge));
    assertThrows(SaslException.class, () -> oversized.evaluateChallenge(new byte[0]));
  }

  @Test
  void negotiatedPropertyRequiresCompletion() {
    PlainSaslClient client =
        new PlainSaslClient(callbacks -> populate(callbacks, "alice", "secret".toCharArray()));
    assertThrows(IllegalStateException.class, () -> client.getNegotiatedProperty(Sasl.QOP));
  }

  private static void populate(Callback[] callbacks, String username, char[] password)
      throws UnsupportedCallbackException {
    for (Callback callback : callbacks) {
      if (callback instanceof NameCallback nameCallback) {
        nameCallback.setName(username);
      } else if (callback instanceof PasswordCallback passwordCallback) {
        passwordCallback.setPassword(password);
      } else {
        throw new UnsupportedCallbackException(callback);
      }
    }
  }
}
