package io.mapsmessaging.sasl.provider.scram.server.state;

import io.mapsmessaging.sasl.provider.scram.State;
import io.mapsmessaging.sasl.provider.scram.msgs.ChallengeResponse;
import io.mapsmessaging.sasl.provider.scram.msgs.FirstClientMessage;
import io.mapsmessaging.sasl.provider.scram.util.SessionContext;
import java.io.IOException;
import java.util.Map;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;

public class InitialState extends State {

  public InitialState(String protocol, String serverName, Map<String, ?> props, CallbackHandler cbh){
    super("", protocol, serverName, props, cbh);
  }

  @Override
  public boolean isComplete() {
    return false;
  }

  @Override
  public ChallengeResponse produceChallenge(SessionContext context) throws IOException, UnsupportedCallbackException {
    context.setServerNonce(nonceGenerator.generateNonce(48));
    ChallengeResponse firstClientChallenge = new FirstClientMessage();
    Callback[] callbacks = new NameCallback[2];
    callbacks[0] = new NameCallback("SCRAM Username Prompt");
    callbacks[1] = new PasswordCallback("SCRAM Password Prompt", false);
    cbh.handle(callbacks);
    String username = ((NameCallback)callbacks[0]).getName();
    if(username == null){
      // Need to log an exception
    }
    char[] password = ((PasswordCallback)callbacks[1]).getPassword();
    firstClientChallenge.put(ChallengeResponse.NONCE, context.getServerNonce());
    firstClientChallenge.put(ChallengeResponse.SALT, new String(password));
    return firstClientChallenge;
  }

  @Override
  public void handeResponse(ChallengeResponse response, SessionContext context) throws IOException, UnsupportedCallbackException {
    // This is the first state, there is no challenge or response
  }
}