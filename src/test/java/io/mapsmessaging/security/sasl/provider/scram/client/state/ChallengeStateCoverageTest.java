/*
 * Copyright [ 2024 - 2026 ] MapsMessaging B.V.
 */
package io.mapsmessaging.security.sasl.provider.scram.client.state;

import static org.junit.jupiter.api.Assertions.*;

import io.mapsmessaging.security.sasl.provider.scram.SessionContext;
import io.mapsmessaging.security.sasl.provider.scram.State;
import io.mapsmessaging.security.sasl.provider.scram.msgs.ChallengeResponse;
import java.util.Base64;
import java.util.Map;
import javax.security.sasl.SaslException;
import org.junit.jupiter.api.Test;

class ChallengeStateCoverageTest {

  @Test
  void rejectsMalformedServerFirstMessages() throws Exception {
    SessionContext context = context();
    ChallengeState state = new ChallengeState(parent(Map.of()));

    assertThrows(
        SaslException.class,
        () -> state.handleResponse(new ChallengeResponse("s=YWJjZA==,r=abcX,i=4096"), context));

    assertThrows(
        SaslException.class,
        () -> state.handleResponse(new ChallengeResponse("r=abcX,s=***,i=4096"), context));

    assertThrows(
        SaslException.class,
        () -> state.handleResponse(
            new ChallengeResponse(
                "r=abcX,s=" + Base64.getEncoder().encodeToString(new byte[4]) + ",i=4096"),
            context));

    assertThrows(
        SaslException.class,
        () -> state.handleResponse(
            new ChallengeResponse(
                "r=abcX,s=" + Base64.getEncoder().encodeToString(new byte[8]) + ",i=nope"),
            context));

    assertThrows(
        SaslException.class,
        () -> state.handleResponse(
            new ChallengeResponse(
                "r=abcX,s=" + Base64.getEncoder().encodeToString(new byte[8]) + ",i=4095"),
            context));
  }

  @Test
  void enforcesConfiguredMaximumIterations() throws Exception {
    SessionContext context = context();
    ChallengeState state =
        new ChallengeState(parent(Map.of(
            "io.mapsmessaging.security.sasl.scram.maxIterations", "5000")));

    assertThrows(
        SaslException.class,
        () -> state.handleResponse(
            new ChallengeResponse(
                "r=abcX,s=" + Base64.getEncoder().encodeToString(new byte[8]) + ",i=5001"),
            context));

    ChallengeState badProperty =
        new ChallengeState(parent(Map.of(
            "io.mapsmessaging.security.sasl.scram.maxIterations", "bad")));
    assertThrows(
        SaslException.class,
        () -> badProperty.handleResponse(
            new ChallengeResponse(
                "r=abcX,s=" + Base64.getEncoder().encodeToString(new byte[8]) + ",i=4096"),
            context));
  }

  private static SessionContext context() {
    SessionContext context = new SessionContext();
    context.setClientNonce("abc");
    return context;
  }

  private static State parent(Map<String, ?> props) {
    return new State(null, "mqtt", "server", props, callbacks -> {}) {
      @Override public boolean isComplete() { return false; }
      @Override public boolean hasInitialResponse() { return true; }
      @Override public ChallengeResponse produceChallenge(SessionContext context) { return null; }
      @Override public void handleResponse(ChallengeResponse response, SessionContext context) {}
    };
  }
}
