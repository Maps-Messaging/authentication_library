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

package io.mapsmessaging.security.sasl;

import io.mapsmessaging.security.access.AuthContext;
import io.mapsmessaging.security.jaas.AuthContextCallback;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.sasl.RealmCallback;

public class ClientCallbackHandler  implements CallbackHandler {

  private final String username;
  private final char[] password;
  private final String serverName;
  private final AuthContext context;

  public ClientCallbackHandler(String username, char[] password, String serverName, AuthContext context) {
    this.username = username;
    this.password = password;
    this.serverName = serverName;
    this.context = context;
  }

  @Override
  public void handle(Callback[] cbs) {
    for (Callback cb : cbs) {
      if (cb instanceof NameCallback nc) {
        nc.setName(username);
      } else if (cb instanceof PasswordCallback pc) {
        pc.setPassword(password);
      } else if (cb instanceof RealmCallback rc) {
        rc.setText(serverName);
      } else if(cb instanceof AuthContextCallback acc){
        acc.setAuthContext(context);
      }
    }
  }
}
