/*
 * Copyright [ 2020 - 2023 ] [Matthew Buckton]
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package io.mapsmessaging.security.sasl.provider.test;

import javax.security.sasl.SaslException;
import javax.security.sasl.SaslServer;

public class TestSaslServer extends TestSasl implements SaslServer {


  public TestSaslServer(String algorithm) {
    String count = algorithm.substring("MAPS-DEBUG-".length());
    loopCount = Integer.parseInt(count);
  }

  @Override
  public String getMechanismName() {
    return "maps";
  }

  @Override
  public byte[] evaluateResponse(byte[] response) throws SaslException {
    return handleServerChallenge(response);
  }

  @Override
  public boolean isComplete() {
    return loopCount == 0;
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
// not required
  }
}
