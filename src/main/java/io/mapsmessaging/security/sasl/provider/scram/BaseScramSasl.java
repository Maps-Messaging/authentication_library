package io.mapsmessaging.security.sasl.provider.scram;

import io.mapsmessaging.logging.Logger;
import io.mapsmessaging.logging.LoggerFactory;
import io.mapsmessaging.security.sasl.provider.scram.msgs.ChallengeResponse;
import io.mapsmessaging.security.sasl.provider.scram.util.SessionContext;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import javax.crypto.Mac;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.sasl.SaslException;

public class BaseScramSasl {

  protected final Logger logger = LoggerFactory.getLogger(BaseScramSasl.class);
  protected final SessionContext context;


  public BaseScramSasl() {
    this.context = new SessionContext();
  }


  protected Mac computeMac(String algorithm) {
    String macLookup = "Hmac" + algorithm.toUpperCase();
    System.err.println("Looking for : " + macLookup);
    Mac mac;
    mac = attemptLookup(macLookup);
    if (mac == null) {
      int idx = macLookup.indexOf("-");
      if (idx > 0) {
        macLookup = macLookup.substring(0, idx) + macLookup.substring(idx + 1);
        System.err.println("Looking for : " + macLookup);
        mac = attemptLookup(macLookup);
      }
    }
    return mac;
  }

  private Mac attemptLookup(String algorithm) {

    try {
      return Mac.getInstance(algorithm.toUpperCase());
    } catch (NoSuchAlgorithmException e) {
      return null;
    }
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

  @SuppressWarnings("java:S1172") // this is a place holder function
  public byte[] unwrap(byte[] incoming, int offset, int len) {
    return new byte[0];
  }

  @SuppressWarnings("java:S1172") // this is a place holder function
  public byte[] wrap(byte[] outgoing, int offset, int len) {
    return new byte[0];
  }

  public void dispose() {
    // this is a place holder
  }
}
