/*
 * Copyright [ 2020 - 2024 ] Matthew Buckton
 *  Copyright [ 2024 - 2025 ] MapsMessaging B.V.
 *
 *  Licensed under the Apache License, Version 2.0 with the Commons Clause
 *  (the "License"); you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at:
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *      https://commonsclause.com/
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 *
 */

package io.mapsmessaging.security.sasl.provider.scram;

import io.mapsmessaging.logging.Logger;
import io.mapsmessaging.logging.LoggerFactory;
import io.mapsmessaging.security.sasl.provider.scram.msgs.ChallengeResponse;
import io.mapsmessaging.security.sasl.provider.utils.XorStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
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
        context.getState().handleResponse(new ChallengeResponse(challenge), context);
      }
      ChallengeResponse challengeResponse = context.getState().produceChallenge(context);
      if (context.getState().isComplete()) {
        inStream = new XorStream(context.getClientKey());
        outStream = new XorStream(context.getClientKey());
      }
      if (challengeResponse != null) {
        return challengeResponse.toString().getBytes(StandardCharsets.UTF_8);
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
