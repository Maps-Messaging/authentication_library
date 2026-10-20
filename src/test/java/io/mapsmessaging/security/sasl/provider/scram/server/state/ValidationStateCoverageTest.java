/*
 * Copyright [ 2024 - 2026 ] MapsMessaging B.V.
 */
package io.mapsmessaging.security.sasl.provider.scram.server.state;

import static org.junit.jupiter.api.Assertions.*;

import io.mapsmessaging.security.sasl.provider.scram.SessionContext;
import io.mapsmessaging.security.sasl.provider.scram.State;
import io.mapsmessaging.security.sasl.provider.scram.msgs.ChallengeResponse;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Map;
import javax.security.sasl.SaslException;
import org.junit.jupiter.api.Test;

class ValidationStateCoverageTest {

  @Test
  void rejectsInvalidClientFinalStructureAndChannelBinding() throws Exception {
    ValidationState state = new ValidationState(parent());
    SessionContext context = context();

    assertThrows(
        SaslException.class,
        () -> state.handleResponse(new ChallengeResponse("r=abcX,p=AAAA"), context));

    assertThrows(
        SaslException.class,
        () -> state.handleResponse(new ChallengeResponse("c=***,r=abcX,p=AAAA"), context));

    String wrongBinding =
        Base64.getEncoder().encodeToString("wrong".getBytes(StandardCharsets.UTF_8));
    assertThrows(
        SaslException.class,
        () -> state.handleResponse(
            new ChallengeResponse("c=" + wrongBinding + ",r=abcX,p=AAAA"), context));
  }

  @Test
  void rejectsNonceAndProofFailures() throws Exception {
    ValidationState state = new ValidationState(parent());
    SessionContext context = context();
    String binding =
        Base64.getEncoder().encodeToString("n,,".getBytes(StandardCharsets.UTF_8));

    assertThrows(
        SaslException.class,
        () -> state.handleResponse(
            new ChallengeResponse("c=" + binding + ",r=other,p=AAAA"), context));

    assertThrows(
        SaslException.class,
        () -> state.handleResponse(
            new ChallengeResponse("c=" + binding + ",r=abcX,p=***"), context));
  }

  @Test
  void producesVerifierAndCompletesState() throws Exception {
    ValidationState state = new ValidationState(parent());
    SessionContext context = context();
    context.setServerSignature(new byte[]{1, 2, 3});

    ChallengeResponse response = state.produceChallenge(context);

    assertEquals(
        Base64.getEncoder().encodeToString(new byte[]{1, 2, 3}),
        response.get(ChallengeResponse.VERIFIER));
    assertTrue(state.isComplete());
    assertTrue(state.hasInitialResponse());
  }

  private static SessionContext context() throws SaslException {
    SessionContext context = new SessionContext();
    context.setGs2Header("n,,");
    context.setClientNonce("abc");
    context.setServerNonce("abcX");
    return context;
  }

  private static State parent() {
    return new State(null, "mqtt", "server", Map.of(), callbacks -> {}) {
      @Override public boolean isComplete() { return false; }
      @Override public boolean hasInitialResponse() { return true; }
      @Override public ChallengeResponse produceChallenge(SessionContext context) { return null; }
      @Override public void handleResponse(ChallengeResponse response, SessionContext context) {}
    };
  }
}
