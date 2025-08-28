/*
 * Copyright [ 2020 - 2024 ] Matthew Buckton
 *  Copyright [ 2024 - 2025 ] MapsMessaging B.V.
 *
 *  Licensed under the Apache License, Version 2.0 with the Commons Clause
 *  (the "License"); you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at:
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *      https://commonsclause.com/
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 *
 */

package io.mapsmessaging.security.passwords.hashes.bcrypt;

import at.favre.lib.crypto.bcrypt.BCrypt.Version;
import io.mapsmessaging.security.passwords.PasswordHasher;

public class BCrypt2APasswordHasher extends BCryptPasswordHasher {

  public BCrypt2APasswordHasher() {
    super(Version.VERSION_2A);
  }

  public BCrypt2APasswordHasher(char[] password) {
    super(password, Version.VERSION_2A);
  }

  public PasswordHasher create(char[] password) {
    return new BCrypt2APasswordHasher(password);
  }

  @Override
  public String getKey() {
    return "$2a$";
  }

}
