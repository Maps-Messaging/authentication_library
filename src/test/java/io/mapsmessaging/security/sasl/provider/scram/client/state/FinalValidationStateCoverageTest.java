/*
 * Copyright [ 2024 - 2026 ] MapsMessaging B.V.
 */
package io.mapsmessaging.security.sasl.provider.scram.client.state;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.mapsmessaging.security.sasl.provider.scram.SessionContext;
import io.mapsmessaging.security.sasl.provider.scram.State;
import io.mapsmessaging.security.sasl.provider.scram.msgs.ChallengeResponse;
import java.io.IOException;
import java.util.Base64;
import java.util.Map;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.sasl.SaslException;
import org.junit.jupiter.api.Test;

class FinalValidationStateCoverageTest {

  @Test
  void acceptsMatchingServerVerifier() throws Exception {
    SessionContext context = new SessionContext();
    context.setServerSignature(new byte[]{1, 2, 3, 4});
    FinalValidationState state = new FinalValidationState(new StubState());

    ChallengeResponse response = new ChallengeResponse();
    response.put(
        ChallengeResponse.VERIFIER,
        Base64.getEncoder().encodeToString(context.getServerSignature()));

    assertTrue(state.hasInitialResponse());
    assertFalse(state.isComplete());
    assertNull(state.produceChallenge(context));

    state.handleResponse(response, context);

    assertTrue(state.isComplete());
  }

  @Test
  void rejectsServerErrorUnexpectedFieldsAndBadVerifier() throws Exception {
    SessionContext context = new SessionContext();
    context.setServerSignature(new byte[]{1, 2, 3, 4});
    FinalValidationState state = new FinalValidationState(new StubState());

    ChallengeResponse serverError = new ChallengeResponse();
    serverError.put(ChallengeResponse.SERVER_ERROR, "invalid-proof");
    assertThrows(SaslException.class, () -> state.handleResponse(serverError, context));

    ChallengeResponse extraField = new ChallengeResponse();
    extraField.put(ChallengeResponse.VERIFIER, "AQIDBA==");
    extraField.put(ChallengeResponse.NONCE, "unexpected");
    assertThrows(SaslException.class, () -> state.handleResponse(extraField, context));

    ChallengeResponse invalidBase64 = new ChallengeResponse();
    invalidBase64.put(ChallengeResponse.VERIFIER, "%%%");
    assertThrows(SaslException.class, () -> state.handleResponse(invalidBase64, context));

    ChallengeResponse wrongSignature = new ChallengeResponse();
    wrongSignature.put(
        ChallengeResponse.VERIFIER,
        Base64.getEncoder().encodeToString(new byte[]{9, 9, 9, 9}));
    assertThrows(SaslException.class, () -> state.handleResponse(wrongSignature, context));
  }

  private static final class StubState extends State {

    private StubState() {
      super(null, "test", "server", Map.of(), callbacks -> {});
    }

    @Override
    public boolean isComplete() {
      return false;
    }

    @Override
    public boolean hasInitialResponse() {
      return false;
    }

    @Override
    public ChallengeResponse produceChallenge(SessionContext context) {
      return null;
    }

    @Override
    public void handleResponse(ChallengeResponse response, SessionContext context)
        throws IOException, UnsupportedCallbackException {
    }
  }
}
