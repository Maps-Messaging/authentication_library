package io.mapsmessaging.sasl.provider.scram.client.state;

import io.mapsmessaging.sasl.provider.scram.msgs.ChallengeResponse;
import io.mapsmessaging.sasl.provider.scram.msgs.FirstClientMessage;
import java.io.IOException;
import java.util.Map;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.UnsupportedCallbackException;

public class InitialState extends State {

  public InitialState(String authorizationId, String protocol, String serverName, Map<String, ?> props, CallbackHandler cbh){
    super(authorizationId, protocol, serverName, props, cbh);
  }

  @Override
  public boolean isComplete() {
    return false;
  }

  @Override
  public ChallengeResponse produceChallenge() throws IOException, UnsupportedCallbackException {
    ChallengeResponse firstClientChallenge = new FirstClientMessage();
    NameCallback[] callbacks = new NameCallback[1];
    callbacks[0] = new NameCallback("SCRAM Username Prompt");
    cbh.handle(callbacks);
    firstClientChallenge.put(ChallengeResponse.USERNAME, callbacks[0].getName());
    firstClientChallenge.putAsBase64Encoded(ChallengeResponse.NONCE, nonceGenerator.generateRandomNonce());
    return firstClientChallenge;
  }

  @Override
  public void handeResponse(ChallengeResponse response) throws IOException, UnsupportedCallbackException {
    // This is the first state, there is no challenge or response
  }
}
