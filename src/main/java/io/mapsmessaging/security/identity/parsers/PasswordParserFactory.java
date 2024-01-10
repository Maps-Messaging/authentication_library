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

package io.mapsmessaging.security.identity.parsers;

import static io.mapsmessaging.security.logging.AuthLogMessages.PASSWORD_PARSER_LOADED;

import io.mapsmessaging.logging.Logger;
import io.mapsmessaging.logging.LoggerFactory;
import io.mapsmessaging.security.identity.parsers.plain.PlainPasswordParser;
import java.util.ArrayList;
import java.util.List;
import java.util.ServiceLoader;
import lombok.Getter;

public class PasswordParserFactory {

  @Getter private static final PasswordParserFactory instance = new PasswordParserFactory();

  private final List<PasswordParser> passwordParsers;
  private final Logger logger = LoggerFactory.getLogger(PasswordParserFactory.class);

  private PasswordParserFactory() {
    passwordParsers = new ArrayList<>();
    ServiceLoader<PasswordParser> list = ServiceLoader.load(PasswordParser.class);
    for (PasswordParser parser : list) {
      passwordParsers.add(parser);
      logger.log(PASSWORD_PARSER_LOADED, parser.getName(), parser.getKey());
    }
  }

  public List<PasswordParser> getPasswordParsers() {
    return new ArrayList<>(passwordParsers);
  }

  public PasswordParser getByClassName(String name) {
    for (PasswordParser passwordParser : passwordParsers) {
      if (passwordParser.getClass().getSimpleName().equals(name)) {
        return passwordParser;
      }
    }
    return null;
  }

  public PasswordParser parse(String password) {
    for (PasswordParser passwordParser : passwordParsers) {
      if (!passwordParser.getName().equals("PLAIN")
          && password.length() >= passwordParser.getKey().length()
          && password.startsWith(passwordParser.getKey())) {
        return passwordParser.create(password);
      }
    }
    return new PlainPasswordParser(password);
  }

}
