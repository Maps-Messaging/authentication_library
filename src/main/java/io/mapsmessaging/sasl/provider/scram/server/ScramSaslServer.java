package io.mapsmessaging.sasl.provider.scram.server;

import io.mapsmessaging.sasl.provider.scram.msgs.ChallengeResponse;
import io.mapsmessaging.sasl.provider.scram.server.state.InitialState;
import io.mapsmessaging.sasl.provider.scram.util.SessionContext;
import java.io.IOException;
import java.util.Map;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.sasl.SaslException;
import javax.security.sasl.SaslServer;

public class ScramSaslServer implements SaslServer {

  private final SessionContext context;

  public ScramSaslServer(String protocol, String serverName, Map<String, ?> props, CallbackHandler cbh) throws SaslException {
    context = new SessionContext();
    context.setState(new InitialState(protocol, serverName, props, cbh));

  }

  @Override
  public String getMechanismName() {
    return null;
  }

  @Override
  public byte[] evaluateResponse(byte[] response) throws SaslException {
    try {
      context.getState().handeResponse(new ChallengeResponse(response), context);
      ChallengeResponse challengeResponse = context.getState().produceChallenge(context);
      if(challengeResponse != null){
        return challengeResponse.toString().getBytes();
      }
      return null;
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
  public String getAuthorizationID() {
    return null;
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
