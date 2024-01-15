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

package io.mapsmessaging.security.passwords;

import static io.mapsmessaging.security.logging.AuthLogMessages.PASSWORD_PARSER_LOADED;

import io.mapsmessaging.logging.Logger;
import io.mapsmessaging.logging.LoggerFactory;
import io.mapsmessaging.security.passwords.hashes.plain.PlainPasswordHasher;
import java.util.ArrayList;
import java.util.List;
import java.util.ServiceLoader;
import lombok.Getter;

public class PasswordHandlerFactory {

  @Getter private static final PasswordHandlerFactory instance = new PasswordHandlerFactory();

  private final List<PasswordHandler> passwordHandlers;
  private final Logger logger = LoggerFactory.getLogger(PasswordHandlerFactory.class);

  private PasswordHandlerFactory() {
    passwordHandlers = new ArrayList<>();
    ServiceLoader<PasswordHandler> list = ServiceLoader.load(PasswordHandler.class);
    for (PasswordHandler parser : list) {
      passwordHandlers.add(parser);
      logger.log(PASSWORD_PARSER_LOADED, parser.getName(), parser.getKey());
    }
  }

  public List<PasswordHandler> getPasswordHashers() {
    return new ArrayList<>(passwordHandlers);
  }

  public PasswordHandler getByClassName(String name) {
    for (PasswordHandler handler : passwordHandlers) {
      if (handler.getClass().getSimpleName().equals(name)) {
        return handler;
      }
    }
    return null;
  }

  public PasswordHandler parse(char[] password) {
    for (PasswordHandler handler : passwordHandlers) {
      if (!handler.getName().equals("PLAIN")
          && password.length >= handler.getKey().length()
          && startWith(password, handler.getKey().toCharArray())) {
        return handler.create(new String(password));
      }
    }
    return new PlainPasswordHasher(new String(password));
  }

  private boolean startWith(char[] longString, char[] start) {
    if (start.length >= longString.length) {
      return false;
    }
    for (int x = 0; x < start.length; x++) {
      if (longString[x] != start[x]) {
        return false;
      }
    }
    return true;
  }

  public PasswordHandler parse(String password) {
    return parse(password.toCharArray());
  }

}
