package io.mapsmessaging.sasl.provider.scram;

import java.util.Map;
import javax.security.auth.callback.CallbackHandler;
import javax.security.sasl.SaslException;
import javax.security.sasl.SaslServer;

public class ScramSaslServer implements SaslServer {

  public ScramSaslServer(String protocol, String serverName, Map<String, ?> props, CallbackHandler cbh) throws SaslException {

  }

  @Override
  public String getMechanismName() {
    return null;
  }

  @Override
  public byte[] evaluateResponse(byte[] response) throws SaslException {
    return new byte[0];
  }

  @Override
  public boolean isComplete() {
    return false;
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
