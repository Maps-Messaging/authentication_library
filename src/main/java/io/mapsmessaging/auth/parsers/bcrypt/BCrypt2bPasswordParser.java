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

package io.mapsmessaging.auth.parsers.bcrypt;

import at.favre.lib.crypto.bcrypt.BCrypt.Version;
import io.mapsmessaging.auth.PasswordParser;
import io.mapsmessaging.auth.parsers.BCryptPasswordParser;

public class BCrypt2bPasswordParser extends BCryptPasswordParser {

  public BCrypt2bPasswordParser() {
    super(Version.VERSION_2B);
  }


  public BCrypt2bPasswordParser(String password) {
    super(password,  Version.VERSION_2B);
  }

  public PasswordParser create(String password) {
    return new BCrypt2bPasswordParser(password);
  }

  @Override
  public String getKey() {
    return "$2b$";
  }
}
