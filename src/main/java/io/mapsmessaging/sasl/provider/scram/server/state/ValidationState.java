package io.mapsmessaging.sasl.provider.scram.server.state;

import io.mapsmessaging.sasl.provider.scram.State;
import io.mapsmessaging.sasl.provider.scram.msgs.ChallengeResponse;
import io.mapsmessaging.sasl.provider.scram.util.SessionContext;
import java.io.IOException;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.sasl.SaslException;

public class ValidationState  extends State {

  private boolean isComplete;

  public ValidationState(State state){
    super(state);
    isComplete = false;
  }

  @Override
  public boolean isComplete() {
    return isComplete;
  }

  @Override
  public ChallengeResponse produceChallenge(SessionContext context) throws IOException, UnsupportedCallbackException {
    ChallengeResponse response = new ChallengeResponse();
    response.put(ChallengeResponse.VERIFIER, "This needs computing");
    isComplete = true;
    return response;
  }

  @Override
  public void handeResponse(ChallengeResponse response, SessionContext context) throws IOException, UnsupportedCallbackException {
    String proof = response.get(ChallengeResponse.PROOF);
    if(!proof.equals("This needs computing")){
      throw new SaslException("Invalid password computed");
    }
  }
}