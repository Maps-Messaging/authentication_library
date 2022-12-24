package io.mapsmessaging.sasl.provider.scram.client;

import io.mapsmessaging.sasl.provider.scram.client.state.InitialState;
import io.mapsmessaging.sasl.provider.scram.State;
import io.mapsmessaging.sasl.provider.scram.msgs.ChallengeResponse;
import io.mapsmessaging.sasl.provider.scram.util.SessionContext;
import java.io.IOException;
import java.util.Map;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.sasl.SaslClient;
import javax.security.sasl.SaslException;

public class ScramSaslClient implements SaslClient {

  private final SessionContext context;

  public ScramSaslClient(String authorizationId, String protocol, String serverName, Map<String, ?> props, CallbackHandler cbh){
    context = new SessionContext();
    context.setState(new InitialState(authorizationId, protocol, serverName, props, cbh));
  }

  @Override
  public String getMechanismName() {
    return null;
  }

  @Override
  public boolean hasInitialResponse() {
    return false;
  }

  @Override
  public byte[] evaluateChallenge(byte[] challenge) throws SaslException {
    try {
      context.getState().handeResponse(new ChallengeResponse(challenge), context);
      return context.getState().produceChallenge(context).toString().getBytes();
    } catch (IOException | UnsupportedCallbackException e) {
      SaslException ex = new SaslException("Exception raised eveluating challenge");
      ex.initCause(e);
      throw ex;
    }
  }

  @Override
  public boolean isComplete() {
    return context.getState().isComplete();
  }

  @Override
  public byte[] unwrap(byte[] incoming, int offset, int len) throws SaslException {
    return new byte[0];
  }

  @Override
  public byte[] wrap(byte[] outgoing, int offset, int len) throws SaslException {
    return new byte[0];
  }

  @Override
  public Object getNegotiatedProperty(String propName) {
    return null;
  }

  @Override
  public void dispose() throws SaslException {

  }
}
