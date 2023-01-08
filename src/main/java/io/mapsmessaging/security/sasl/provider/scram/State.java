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

package io.mapsmessaging.security.sasl.provider.scram;

import io.mapsmessaging.logging.Logger;
import io.mapsmessaging.logging.LoggerFactory;
import io.mapsmessaging.security.sasl.provider.scram.msgs.ChallengeResponse;
import io.mapsmessaging.security.sasl.provider.scram.util.NonceGenerator;
import io.mapsmessaging.security.sasl.provider.scram.util.SessionContext;
import java.io.IOException;
import java.util.Map;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;

public abstract class State {

  protected final Logger logger = LoggerFactory.getLogger(State.class);
  protected final String authorizationId;
  protected final String protocol;
  protected final String serverName;
  protected final Map<String, ?> props;
  protected final CallbackHandler cbh;
  protected final NonceGenerator nonceGenerator;

  protected State(String authorizationId, String protocol, String serverName, Map<String, ?> props, CallbackHandler cbh) {
    this.authorizationId = authorizationId;
    this.props = props;
    this.protocol = protocol;
    this.serverName = serverName;
    this.cbh = cbh;
    nonceGenerator = new NonceGenerator();
  }

  protected State(State lhs) {
    this.authorizationId = lhs.authorizationId;
    this.props = lhs.props;
    this.protocol = lhs.protocol;
    this.serverName = lhs.serverName;
    this.cbh = lhs.cbh;
    nonceGenerator = lhs.nonceGenerator;
  }

  public abstract boolean isComplete();

  public abstract boolean hasInitialResponse();

  public abstract ChallengeResponse produceChallenge(SessionContext context) throws IOException, UnsupportedCallbackException;

  public abstract void handeResponse(ChallengeResponse response, SessionContext context) throws IOException, UnsupportedCallbackException;
}
