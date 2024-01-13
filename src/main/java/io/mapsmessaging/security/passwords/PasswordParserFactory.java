/*
 * Copyright [ 2020 - 2024 ] [Matthew Buckton]
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

package io.mapsmessaging.security.passwords;

import io.mapsmessaging.logging.Logger;
import io.mapsmessaging.logging.LoggerFactory;
import io.mapsmessaging.security.passwords.hashes.plain.PlainPasswordHasher;
import lombok.Getter;

import java.util.ArrayList;
import java.util.List;
import java.util.ServiceLoader;

import static io.mapsmessaging.security.logging.AuthLogMessages.PASSWORD_PARSER_LOADED;

public class PasswordParserFactory {

  @Getter
  private static final PasswordParserFactory instance = new PasswordParserFactory();

  private final List<PasswordHandler> passwordHandlers;
  private final Logger logger = LoggerFactory.getLogger(PasswordParserFactory.class);

  private PasswordParserFactory() {
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

  public PasswordHandler parse(String password) {
    for (PasswordHandler handler : passwordHandlers) {
      if (!handler.getName().equals("PLAIN")
          && password.length() >= handler.getKey().length()
          && password.startsWith(handler.getKey())) {
        return handler.create(password);
      }
    }
    return new PlainPasswordHasher(password);
  }

}
