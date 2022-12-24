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

import java.util.StringTokenizer;
import lombok.Getter;

public class IdentityEntry {

  @Getter
  private final String username;
  @Getter
  private final HashType hashType;
  @Getter
  private final char[] passwordHash;
  @Getter
  private final String salt;

  public IdentityEntry(String line) {
    int usernamePos = line.indexOf(":");
    username = line.substring(0, usernamePos);
    line = line.substring(usernamePos + 1);

    hashType = HashType.detect(line);
    line = line.substring(hashType.getName().length());
    switch (hashType) {
      case SHA1:
        salt = "";
        passwordHash = line.toCharArray();
        break;

      case MD5:
        StringTokenizer stringTokenizer = new StringTokenizer(line, "$");
        salt = stringTokenizer.nextElement().toString();
        passwordHash = stringTokenizer.nextElement().toString().toCharArray();
        break;

      case BCRYPT:
        stringTokenizer = new StringTokenizer(line, "$");
        salt = stringTokenizer.nextElement().toString();
        passwordHash = stringTokenizer.nextElement().toString().toCharArray();
        break;

      default:
        passwordHash = line.toCharArray();
        salt = "";
    }
  }

  @Override
  public String toString() {
    switch (hashType) {
      case MD5:
      case BCRYPT:
        return username + ":" + hashType.getName() + salt + "$" + new String(passwordHash) + "\n";

      case SHA1:
        return username + ":" + hashType.getName() + new String(passwordHash) + "\n";

      case PLAIN:
      default:
        return username + ":" + new String(passwordHash) + "\n";
    }
  }
}
