/*
 * Copyright [ 2024 - 2026 ] MapsMessaging B.V.
 */
package io.mapsmessaging.security.sasl.provider.scram.server.state;

import static org.junit.jupiter.api.Assertions.*;

import io.mapsmessaging.security.sasl.provider.scram.SessionContext;
import io.mapsmessaging.security.sasl.provider.scram.msgs.ChallengeResponse;
import java.util.Base64;
import java.util.Map;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.sasl.SaslException;
import org.junit.jupiter.api.Test;

class InitialStateCoverageTest {

  @Test
  void handlesValidClientFirstAndProducesServerChallenge() throws Exception {
    InitialState state = new InitialState("mqtt", "server", Map.of(), callbacks -> password(callbacks, "secret"));
    SessionContext context = new SessionContext();

    assertFalse(state.isComplete());
    assertTrue(state.hasInitialResponse());
    assertNull(state.produceChallenge(context));

    ChallengeResponse request = new ChallengeResponse("n,,n=alice,r=clientNonce");
    state.handleResponse(request, context);

    assertEquals("alice", context.getUsername());
    assertEquals("clientNonce", context.getClientNonce());
    assertEquals("n,,", context.getGs2Header());
    assertNull(context.getAuthorizationId());
    assertTrue(context.isReceivedClientMessage());
    assertTrue(context.isAuthenticationIdentityValid());
    assertEquals(10_000, context.getIterations());
    assertEquals(16, context.getPasswordSalt().length);
    assertTrue(context.getServerNonce().startsWith("clientNonce"));

    ChallengeResponse response = state.produceChallenge(context);
    assertEquals(context.getServerNonce(), response.get(ChallengeResponse.NONCE));
    assertEquals(Base64.getEncoder().encodeToString(context.getPasswordSalt()),
        response.get(ChallengeResponse.SALT));
    assertEquals("10000", response.get(ChallengeResponse.ITERATION_COUNT));
    assertInstanceOf(ValidationState.class, context.getState());
  }

  @Test
  void handlesAuthorizationIdentityAndConfiguredIterations() throws Exception {
    InitialState state =
        new InitialState(
            "mqtt",
            "server",
            Map.of("io.mapsmessaging.security.sasl.scram.iterations", "4096"),
            callbacks -> password(callbacks, "secret"));
    SessionContext context = new SessionContext();

    state.handleResponse(new ChallengeResponse("n,a=admin,n=alice,r=nonce"), context);

    assertEquals("admin", context.getAuthorizationId());
    assertEquals(4096, context.getIterations());
  }

  @Test
  void rejectsMalformedMessagesAndIterationProperties() throws Exception {
    InitialState state = new InitialState("mqtt", "server", Map.of(), callbacks -> password(callbacks, "secret"));

    assertThrows(
        SaslException.class,
        () -> state.handleResponse(new ChallengeResponse("n=alice,r=nonce"), new SessionContext()));
    assertThrows(
        SaslException.class,
        () -> state.handleResponse(new ChallengeResponse("n,,r=nonce,n=alice"), new SessionContext()));
    assertThrows(
        SaslException.class,
        () -> state.handleResponse(new ChallengeResponse("n,,n=alice,r="), new SessionContext()));

    InitialState badNumber =
        new InitialState(
            "mqtt",
            "server",
            Map.of("io.mapsmessaging.security.sasl.scram.iterations", "bad"),
            callbacks -> password(callbacks, "secret"));
    assertThrows(
        SaslException.class,
        () -> badNumber.handleResponse(new ChallengeResponse("n,,n=alice,r=nonce"), new SessionContext()));

    InitialState tooLow =
        new InitialState(
            "mqtt",
            "server",
            Map.of("io.mapsmessaging.security.sasl.scram.iterations", "4095"),
            callbacks -> password(callbacks, "secret"));
    assertThrows(
        SaslException.class,
        () -> tooLow.handleResponse(new ChallengeResponse("n,,n=alice,r=nonce"), new SessionContext()));

    InitialState tooHigh =
        new InitialState(
            "mqtt",
            "server",
            Map.of("io.mapsmessaging.security.sasl.scram.iterations", "1000001"),
            callbacks -> password(callbacks, "secret"));
    assertThrows(
        SaslException.class,
        () -> tooHigh.handleResponse(new ChallengeResponse("n,,n=alice,r=nonce"), new SessionContext()));
  }

  @Test
  void unknownIdentityUsesDummyPasswordPath() throws Exception {
    InitialState state =
        new InitialState(
            "mqtt",
            "server",
            Map.of(),
            callbacks -> {
              for (Callback callback : callbacks) {
                if (callback instanceof NameCallback nameCallback) {
                  nameCallback.setName(null);
                } else if (callback instanceof PasswordCallback passwordCallback) {
                  passwordCallback.setPassword(null);
                }
              }
            });
    SessionContext context = new SessionContext();

    state.handleResponse(new ChallengeResponse("n,,n=missing,r=nonce"), context);

    assertFalse(context.isAuthenticationIdentityValid());
    assertNotNull(context.getPrepPassword());
    assertTrue(context.getPrepPassword().length > 0);
  }

  private static void password(Callback[] callbacks, String password)
      throws UnsupportedCallbackException {
    for (Callback callback : callbacks) {
      if (callback instanceof NameCallback nameCallback) {
        nameCallback.setName(nameCallback.getDefaultName());
      } else if (callback instanceof PasswordCallback passwordCallback) {
        passwordCallback.setPassword(password.toCharArray());
      } else {
        throw new UnsupportedCallbackException(callback);
      }
    }
  }
}
