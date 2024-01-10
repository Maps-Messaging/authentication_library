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

package io.mapsmessaging.security.identity.parsers.pbkdf2;

import io.mapsmessaging.security.identity.parsers.PasswordParser;

public class Pdkdf2Sha3512PasswordParser extends Pbkdf2Sha3PasswordParser {

  private static final int HASH_BYTE_SIZE = 64;
  private static final String PBKDF2_ALGORITHM = "PBKDF2WithHmacSHA3-512";
  private static final int PBKDF2_ITERATIONS = 10000;

  public Pdkdf2Sha3512PasswordParser() {
    super("");
  }

  public Pdkdf2Sha3512PasswordParser(String password) {
    super(password);
  }

  @Override
  protected String getAlgorithm() {
    return PBKDF2_ALGORITHM;
  }

  @Override
  protected int getIterationCount() {
    return PBKDF2_ITERATIONS;
  }

  @Override
  public PasswordParser create(String password) {
    return new Pdkdf2Sha3512PasswordParser(password);
  }

  @Override
  public String getName() {
    return "PBKDF2-SHA3-512";
  }

  @Override
  protected int getHashByteSize() {
    return HASH_BYTE_SIZE;
  }
}
