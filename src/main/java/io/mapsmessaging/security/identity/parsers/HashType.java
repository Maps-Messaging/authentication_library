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

package io.mapsmessaging.security.identity.parsers;

import io.mapsmessaging.security.identity.parsers.bcrypt.BCrypt2yPasswordParser;
import lombok.Getter;

public enum HashType {
  PLAIN("", new PlainPasswordParser()),
  MD5("$apr1$", new Md5PasswordParser()),
  SHA1("{SHA}", new Sha1PasswordParser()),
  BCRYPT("$2y$", new BCrypt2yPasswordParser());

  @Getter
  private final String name;

  @Getter
  private final PasswordParser passwordParser;

  HashType(String name, PasswordParser passwordParser) {
    this.name = name;
    this.passwordParser = passwordParser;
  }
}
