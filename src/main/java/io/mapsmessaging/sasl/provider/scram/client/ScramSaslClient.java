/*
 * Copyright [ 2020 - 2022 ] [Matthew Buckton]
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package io.mapsmessaging.sasl.provider.scram.client;

import io.mapsmessaging.sasl.provider.scram.client.state.InitialState;
import io.mapsmessaging.sasl.provider.scram.msgs.ChallengeResponse;
import io.mapsmessaging.sasl.provider.scram.util.SessionContext;
import java.io.IOException;
import java.util.Map;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.sasl.Sasl;
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
    if(propName.equals(Sasl.QOP)){
      return "auth";
    }
    return null;
  }

  @Override
  public void dispose() throws SaslException {

  }
}
