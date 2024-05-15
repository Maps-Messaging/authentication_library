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
import io.mapsmessaging.security.util.ArrayHelper;
import java.util.ArrayList;
import java.util.List;
import java.util.ServiceLoader;

@SuppressWarnings("java:S6548")
public class PasswordHandlerFactory {


  private static class Holder {
    static final PasswordHandlerFactory INSTANCE = new PasswordHandlerFactory();
  }

  public static PasswordHandlerFactory getInstance() {
    return PasswordHandlerFactory.Holder.INSTANCE;
  }

  private final List<PasswordHandler> passwordHandlers;

  private PasswordHandlerFactory() {
    Logger logger = LoggerFactory.getLogger(PasswordHandlerFactory.class);
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
      char[] key = handler.getKey().toCharArray();
      if (!handler.getName().equals("PLAIN")
          && password.length >= key.length
          && ArrayHelper.startsWithIgnoreCase(password, key)) {
        return handler.create(password);
      }
    }
    return new PlainPasswordHasher(password);
  }

}
