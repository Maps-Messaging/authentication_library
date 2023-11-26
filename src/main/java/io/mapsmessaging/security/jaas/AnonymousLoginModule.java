/*
 * Copyright [ 2020 - 2023 ] [Matthew Buckton]
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

package io.mapsmessaging.security.jaas;

import com.sun.security.auth.UserPrincipal;

import javax.security.auth.login.LoginException;

import static io.mapsmessaging.security.logging.AuthLogMessages.DO_NOT_USE_IN_PRODUCTION;

public class AnonymousLoginModule extends BaseLoginModule {

  public AnonymousLoginModule() {
    super();
    username = "anonymous";
    logger.log(DO_NOT_USE_IN_PRODUCTION);
  }

  @Override
  public boolean login() {
    userPrincipal = new UserPrincipal(username);
    succeeded = true;
    return true;
  }

  @Override
  protected boolean validate(String username, char[] password) throws LoginException {
    return true;
  }
}
