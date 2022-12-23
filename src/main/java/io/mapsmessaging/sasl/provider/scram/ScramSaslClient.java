package io.mapsmessaging.sasl.provider.scram;

import java.util.Map;
import javax.security.auth.callback.CallbackHandler;
import javax.security.sasl.SaslClient;
import javax.security.sasl.SaslException;

public class ScramSaslClient implements SaslClient {

  public ScramSaslClient(String authorizationId, String protocol, String serverName, Map<String, ?> props, CallbackHandler cbh){

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
    return new byte[0];
  }

  @Override
  public boolean isComplete() {
    return false;
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
