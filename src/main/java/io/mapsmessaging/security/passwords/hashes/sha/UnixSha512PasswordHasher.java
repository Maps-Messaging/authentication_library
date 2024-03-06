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

package io.mapsmessaging.security.passwords.hashes.sha;

import io.mapsmessaging.security.passwords.PasswordHasher;

public class UnixSha512PasswordHasher extends UnixShaPasswordHasher {

  private static final String KEY = "$6$";

  public UnixSha512PasswordHasher() {
    this(KEY);
  }

  public UnixSha512PasswordHasher(String password) {
    super(KEY, password);
  }

  @Override
  public PasswordHasher create(String password) {
    return new UnixSha512PasswordHasher(password);
  }

  @Override
  public String getName() {
    return "UNIX-SHA-512";
  }

}
