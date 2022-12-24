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

package io.mapsmessaging.sasl.impl.htpasswd;

import io.mapsmessaging.sasl.impl.htpasswd.hash.BCryptPasswordHash;
import io.mapsmessaging.sasl.impl.htpasswd.hash.MD5PasswordHash;
import io.mapsmessaging.sasl.impl.htpasswd.hash.PasswordHash;
import io.mapsmessaging.sasl.impl.htpasswd.hash.PlainPasswordHash;
import io.mapsmessaging.sasl.impl.htpasswd.hash.Sha1PasswordHash;
import lombok.Getter;

public enum HashType {
  PLAIN("", new PlainPasswordHash()),
  MD5("$apr1$", new MD5PasswordHash()),
  SHA1("{SHA}", new Sha1PasswordHash()),
  BCRYPT("$2y$", new BCryptPasswordHash());

  @Getter
  private final String name;

  @Getter
  private final PasswordHash passwordHash;

  HashType(String name, PasswordHash passwordHash) {
    this.name = name;
    this.passwordHash = passwordHash;
  }

  public static HashType detect(String type) {
    String test = type.toLowerCase();
    if (test.startsWith("$apr1$")) {
      return MD5;
    } else if (test.startsWith("{sha}")) {
      return SHA1;
    } else if (test.startsWith("$2y$")) {
      return BCRYPT;
    }
    return PLAIN;
  }
}
