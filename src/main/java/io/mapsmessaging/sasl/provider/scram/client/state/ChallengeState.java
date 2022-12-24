package io.mapsmessaging.sasl.provider.scram.client.state;

import io.mapsmessaging.sasl.provider.scram.State;
import io.mapsmessaging.sasl.provider.scram.msgs.ChallengeResponse;
import io.mapsmessaging.sasl.provider.scram.util.SessionContext;
import java.io.IOException;
import javax.security.auth.callback.UnsupportedCallbackException;

public class ChallengeState extends State {

  public ChallengeState(State state){
    super(state);
  }

  @Override
  public boolean isComplete() {
    return false;
  }

  @Override
  public ChallengeResponse produceChallenge(SessionContext context) throws IOException, UnsupportedCallbackException {
    ChallengeResponse response = new ChallengeResponse();
    response.put(ChallengeResponse.NONCE, context.getServerNonce());
    response.put(ChallengeResponse.PROOF, "This needs computing");
    context.setState(new FinalValidationState(this));
    return response;
  }

  @Override
  public void handeResponse(ChallengeResponse response, SessionContext context) throws IOException, UnsupportedCallbackException {
    context.setServerNonce(response.get(ChallengeResponse.NONCE));
    context.setPasswordSalt(response.get(ChallengeResponse.SALT));
    context.setInterations(Integer.parseInt(response.get(ChallengeResponse.ITERATION_COUNT)));

  }
}
