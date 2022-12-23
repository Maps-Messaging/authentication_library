package io.mapsmessaging.sasl.provider.scram.client.state;

import io.mapsmessaging.sasl.provider.scram.msgs.ChallengeResponse;
import io.mapsmessaging.sasl.provider.scram.util.NonceGenerator;
import java.io.IOException;
import java.util.Map;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;

public abstract class State {

  protected final String authorizationId;
  protected final String protocol;
  protected final String serverName;
  protected final Map<String, ?> props;
  protected final CallbackHandler cbh;
  protected final NonceGenerator nonceGenerator;

  protected State(String authorizationId, String protocol, String serverName, Map<String, ?> props, CallbackHandler cbh){
    this.authorizationId = authorizationId;
    this.props = props;
    this.protocol = protocol;
    this.serverName = serverName;
    this.cbh = cbh;
    nonceGenerator = new NonceGenerator();
  }

  public abstract boolean isComplete();

  public abstract ChallengeResponse produceChallenge() throws IOException, UnsupportedCallbackException;

  public abstract void handeResponse(ChallengeResponse response ) throws IOException, UnsupportedCallbackException;
}
