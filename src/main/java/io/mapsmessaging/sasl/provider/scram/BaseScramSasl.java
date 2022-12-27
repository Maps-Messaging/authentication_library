package io.mapsmessaging.sasl.provider.scram;

import io.mapsmessaging.sasl.provider.scram.msgs.ChallengeResponse;
import io.mapsmessaging.sasl.provider.scram.util.SessionContext;
import java.io.IOException;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.sasl.SaslException;

public class BaseScramSasl {

  protected final SessionContext context;

  public BaseScramSasl(){
    this.context = new SessionContext();
  }

  public boolean isComplete() {
    return context.getState().isComplete();
  }

  public byte[] evaluateChallenge(byte[] challenge) throws SaslException {
    try {
      if(challenge != null){
        context.getState().handeResponse(new ChallengeResponse(challenge), context);
      }
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

  public byte[] unwrap(byte[] incoming, int offset, int len) throws SaslException {
    return new byte[0];
  }

  public byte[] wrap(byte[] outgoing, int offset, int len) throws SaslException {
    return new byte[0];
  }

  public void dispose() throws SaslException {
  }
}
