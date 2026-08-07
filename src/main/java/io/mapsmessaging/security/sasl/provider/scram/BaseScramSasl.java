/*
 * Copyright [ 2020 - 2024 ] Matthew Buckton
 *  Copyright [ 2024 - 2026 ] MapsMessaging B.V.
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
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.sasl.SaslException;

public class BaseScramSasl {

  private static final int MAX_MESSAGE_SIZE = 16 * 1024;

  protected final Logger logger = LoggerFactory.getLogger(BaseScramSasl.class);
  protected final SessionContext context = new SessionContext();
  private boolean disposed;

  public boolean isComplete() {
    return !disposed && context.getState() != null && context.getState().isComplete();
  }

  @SuppressWarnings("java:S1168")
  public byte[] evaluateChallenge(byte[] challenge) throws SaslException {
    if (disposed) {
      throw new SaslException("SCRAM exchange has been disposed");
    }
    if (isComplete()) {
      throw new SaslException("SCRAM exchange is already complete");
    }
    if (challenge != null && challenge.length > MAX_MESSAGE_SIZE) {
      throw new SaslException("SCRAM message exceeds the maximum size");
    }
    try {
      if (challenge != null && challenge.length != 0) {
        context.getState().handleResponse(new ChallengeResponse(challenge), context);
      }
      ChallengeResponse response = context.getState().produceChallenge(context);
      return response == null ? null : response.toString().getBytes(StandardCharsets.UTF_8);
    } catch (IOException | UnsupportedCallbackException | IllegalArgumentException e) {
      throw new SaslException("Invalid SCRAM exchange", e);
    }
  }

  public byte[] unwrap(byte[] incoming, int offset, int len) throws SaslException {
    throw new IllegalStateException("SCRAM does not negotiate a security layer");
  }

  public byte[] wrap(byte[] outgoing, int offset, int len) throws SaslException {
    throw new IllegalStateException("SCRAM does not negotiate a security layer");
  }

  public void dispose() throws SaslException {
    if (!disposed) {
      context.reset();
      disposed = true;
    }
  }

  protected void requireComplete() {
    if (!isComplete()) {
      throw new IllegalStateException("SCRAM authentication is not complete");
    }
  }
}
