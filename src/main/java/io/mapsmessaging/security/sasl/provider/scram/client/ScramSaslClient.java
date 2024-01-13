/*
 * Copyright [ 2020 - 2024 ] [Matthew Buckton]
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

package io.mapsmessaging.security.sasl.provider.scram.client;

import io.mapsmessaging.security.passwords.hashes.bcrypt.BCrypt2YPasswordHasher;
import io.mapsmessaging.security.passwords.hashes.pbkdf2.Pbkdf2Sha256PasswordHasher;
import io.mapsmessaging.security.passwords.hashes.pbkdf2.Pbkdf2Sha3256PasswordHasher;
import io.mapsmessaging.security.passwords.hashes.pbkdf2.Pbkdf2Sha512PasswordHasher;
import io.mapsmessaging.security.passwords.hashes.pbkdf2.Pdkdf2Sha3512PasswordHasher;
import io.mapsmessaging.security.sasl.provider.scram.BaseScramSasl;
import io.mapsmessaging.security.sasl.provider.scram.client.state.InitialState;
import io.mapsmessaging.security.sasl.provider.scram.crypto.CryptoHelper;

import javax.security.auth.callback.CallbackHandler;
import javax.security.sasl.Sasl;
import javax.security.sasl.SaslClient;
import java.security.NoSuchAlgorithmException;
import java.util.Map;

public class ScramSaslClient extends BaseScramSasl implements SaslClient {

  public ScramSaslClient(String algorithm, String authorizationId, String protocol, String serverName, Map<String, ?> props, CallbackHandler cbh) throws NoSuchAlgorithmException {
    if (algorithm.startsWith("bcrypt")) {
      context.setPasswordHasher(new BCrypt2YPasswordHasher());
      algorithm = algorithm.substring("bcrypt-".length());
    } else {
      if (algorithm.equalsIgnoreCase("sha-256")) {
        context.setPasswordHasher(new Pbkdf2Sha256PasswordHasher());
      } else if (algorithm.equalsIgnoreCase("sha-512")) {
        context.setPasswordHasher(new Pbkdf2Sha512PasswordHasher());
      } else if (algorithm.equalsIgnoreCase("sha3-256")) {
        context.setPasswordHasher(new Pbkdf2Sha3256PasswordHasher());
      } else if (algorithm.equalsIgnoreCase("sha3-512")) {
        context.setPasswordHasher(new Pdkdf2Sha3512PasswordHasher());
      }
    }
    context.setMac(CryptoHelper.findMac(algorithm));
    context.setState(new InitialState(authorizationId, protocol, serverName, props, cbh));
  }

  @Override
  public String getMechanismName() {
    return "SCRAM";
  }

  @Override
  public boolean hasInitialResponse() {
    return context.getState().hasInitialResponse();
  }

  @Override
  public Object getNegotiatedProperty(String propName) {
    if (propName.equals(Sasl.QOP)) {
      return "auth-conf";
    }
    return null;
  }
}
