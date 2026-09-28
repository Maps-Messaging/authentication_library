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
import javax.security.sasl.AuthorizeCallback;
import javax.security.sasl.Sasl;
import javax.security.sasl.SaslException;
import org.junit.jupiter.api.Test;

class PlainSaslServerCoverageTest {

  @Test
  void authenticatesAndAuthorizesPlainResponse() throws Exception {
    PlainSaslServer server = new PlainSaslServer(callbacks -> handle(callbacks, true));

    byte[] result = server.evaluateResponse("\0alice\0secret".getBytes(StandardCharsets.UTF_8));

    assertArrayEquals(new byte[0], result);
    assertTrue(server.isComplete());
    assertEquals("alice", server.getAuthorizationID());
    assertEquals("auth", server.getNegotiatedProperty(Sasl.QOP));
    assertNull(server.getNegotiatedProperty("other"));
    assertEquals("PLAIN", server.getMechanismName());

    assertThrows(SaslException.class, () -> server.evaluateResponse(new byte[]{1}));
    assertThrows(IllegalStateException.class, () -> server.wrap(new byte[1], 0, 1));
    assertThrows(IllegalStateException.class, () -> server.unwrap(new byte[1], 0, 1));

    server.dispose();
    assertFalse(server.isComplete());
  }

  @Test
  void supportsExplicitAuthorizationIdentity() throws Exception {
    PlainSaslServer server = new PlainSaslServer(callbacks -> handle(callbacks, true));
    server.evaluateResponse("admin\0alice\0secret".getBytes(StandardCharsets.UTF_8));
    assertEquals("admin", server.getAuthorizationID());
  }

  @Test
  void rejectsMalformedResponses() {
    PlainSaslServer server = new PlainSaslServer(callbacks -> handle(callbacks, true));

    assertThrows(SaslException.class, () -> server.evaluateResponse(null));
    assertThrows(SaslException.class, () -> server.evaluateResponse(new byte[0]));
    assertThrows(SaslException.class, () -> server.evaluateResponse("alice".getBytes(StandardCharsets.UTF_8)));
    assertThrows(SaslException.class, () -> server.evaluateResponse("\0\0secret".getBytes(StandardCharsets.UTF_8)));
    assertThrows(SaslException.class, () -> server.evaluateResponse("\0alice\0".getBytes(StandardCharsets.UTF_8)));
    assertThrows(SaslException.class, () -> server.evaluateResponse("\0alice\0secret\0extra".getBytes(StandardCharsets.UTF_8)));

    byte[] huge = new byte[17_000];
    assertThrows(SaslException.class, () -> server.evaluateResponse(huge));
  }

  @Test
  void rejectsInvalidUtf8WrongPasswordAndUnauthorizedIdentity() {
    PlainSaslServer invalidUtf8 = new PlainSaslServer(callbacks -> handle(callbacks, true));
    assertThrows(
        SaslException.class,
        () -> invalidUtf8.evaluateResponse(new byte[]{0, 'a', 0, (byte) 0xC3, 0x28}));

    PlainSaslServer wrongPassword = new PlainSaslServer(callbacks -> handle(callbacks, true));
    assertThrows(
        SaslException.class,
        () -> wrongPassword.evaluateResponse("\0alice\0wrong".getBytes(StandardCharsets.UTF_8)));

    PlainSaslServer unauthorized = new PlainSaslServer(callbacks -> handle(callbacks, false));
    assertThrows(
        SaslException.class,
        () -> unauthorized.evaluateResponse("\0alice\0secret".getBytes(StandardCharsets.UTF_8)));
  }

  @Test
  void wrapsCallbackFailuresAndRequiresCompletion() {
    PlainSaslServer callbackFailure =
        new PlainSaslServer(callbacks -> { throw new IOException("boom"); });
    assertThrows(
        SaslException.class,
        () -> callbackFailure.evaluateResponse("\0alice\0secret".getBytes(StandardCharsets.UTF_8)));

    PlainSaslServer server = new PlainSaslServer(callbacks -> handle(callbacks, true));
    assertThrows(IllegalStateException.class, server::getAuthorizationID);
    assertThrows(IllegalStateException.class, () -> server.getNegotiatedProperty(Sasl.QOP));
  }

  private static void handle(Callback[] callbacks, boolean authorize)
      throws UnsupportedCallbackException {
    for (Callback callback : callbacks) {
      if (callback instanceof NameCallback nameCallback) {
        nameCallback.setName(nameCallback.getDefaultName());
      } else if (callback instanceof PasswordCallback passwordCallback) {
        passwordCallback.setPassword("secret".toCharArray());
      } else if (callback instanceof AuthorizeCallback authorizeCallback) {
        authorizeCallback.setAuthorized(authorize);
        if (authorize) {
          authorizeCallback.setAuthorizedID(authorizeCallback.getAuthorizationID());
        }
      } else {
        throw new UnsupportedCallbackException(callback);
      }
    }
  }
}
