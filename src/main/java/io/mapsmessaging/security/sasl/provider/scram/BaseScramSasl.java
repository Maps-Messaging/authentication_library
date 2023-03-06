package io.mapsmessaging.security.sasl.provider.scram;

import io.mapsmessaging.logging.Logger;
import io.mapsmessaging.logging.LoggerFactory;
import io.mapsmessaging.security.sasl.provider.scram.msgs.ChallengeResponse;
import java.io.IOException;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.sasl.SaslException;

public class BaseScramSasl {

  protected final Logger logger = LoggerFactory.getLogger(BaseScramSasl.class);
  protected final SessionContext context;
  private XorStream inStream;
  private XorStream outStream;

  public BaseScramSasl() {
    this.context = new SessionContext();
  }

  public boolean isComplete() {
    return context.getState().isComplete();
  }

  @SuppressWarnings("java:S1168") // We return null since it needs to be
  public byte[] evaluateChallenge(byte[] challenge) throws SaslException {
    try {
      if (challenge != null) {
        context.getState().handeResponse(new ChallengeResponse(challenge), context);
      }
      ChallengeResponse challengeResponse = context.getState().produceChallenge(context);
      if (context.getState().isComplete()) {
        inStream = new XorStream(context.getClientKey());
        outStream = new XorStream(context.getClientKey());
      }
      if (challengeResponse != null) {
        return challengeResponse.toString().getBytes();
      }
      return null;
    } catch (IOException | UnsupportedCallbackException e) {
      SaslException ex = new SaslException("Exception raised eveluating challenge");
      ex.initCause(e);
      throw ex;
    }
  }

  public byte[] unwrap(byte[] incoming, int offset, int len) {
    return inStream.xorBuffer(incoming, offset, len);
  }

  public byte[] wrap(byte[] outgoing, int offset, int len) {
    return outStream.xorBuffer(outgoing, offset, len);
  }

  public void dispose() {
    context.reset();
  }

}
