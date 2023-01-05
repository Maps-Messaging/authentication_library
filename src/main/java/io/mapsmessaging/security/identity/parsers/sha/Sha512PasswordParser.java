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

package io.mapsmessaging.security.identity.parsers.sha;

import io.mapsmessaging.security.identity.parsers.PasswordParser;

public class Sha512PasswordParser extends ShaPasswordParser {

  public Sha512PasswordParser() {
    this("$6$");
  }

  public Sha512PasswordParser(String password) {
    super("$6$", password.substring("$6$".length()));
  }

  @Override
  public PasswordParser create(String password) {
    return new Sha512PasswordParser(password);
  }

  @Override
  public String getName() {
    return "SHA-512";
  }
}
