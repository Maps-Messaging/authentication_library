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

package io.mapsmessaging.sasl.provider.scram.util;

import java.security.SecureRandom;

public class NonceGenerator {

  private static final byte[] NONCE_CHARS = "+abcdefghijklmnopqrstuvwxyz01234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ".getBytes();

  private final SecureRandom prng;

  public NonceGenerator() {
    prng = new SecureRandom();
  }

  public String generateNonce(int size) {
    byte[] nonce = new byte[size];
    int x = 0;
    while(x<size){
      int idx = Math.abs(prng.nextInt(NONCE_CHARS.length));
      nonce[x] = NONCE_CHARS[idx];
      x++;
    }
    return new String(nonce);
  }
}
