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

package io.mapsmessaging.security.passwords.hashes.pbkdf2;

import io.mapsmessaging.security.passwords.PasswordHasher;

public class Pbkdf2Sha256PasswordHasher extends Pbkdf2PasswordHasher {
  private static final int HASH_BYTE_SIZE = 32;
  private static final String PBKDF2_ALGORITHM = "PBKDF2WithHmacSHA256";
  private static final int PBKDF2_ITERATIONS = 10000;

  public Pbkdf2Sha256PasswordHasher() {
    super(new char[0]);
  }

  public Pbkdf2Sha256PasswordHasher(char[] password) {
    super(password);
  }

  @Override
  public String getAlgorithm() {
    return PBKDF2_ALGORITHM;
  }

  @Override
  protected int getIterationCount() {
    return PBKDF2_ITERATIONS;
  }

  @Override
  public PasswordHasher create(char[] password) {
    return new Pbkdf2Sha256PasswordHasher(password);
  }

  @Override
  public String getName() {
    return "PBKDF2-SHA256";
  }

  @Override
  protected int getHashByteSize() {
    return HASH_BYTE_SIZE;
  }
}
