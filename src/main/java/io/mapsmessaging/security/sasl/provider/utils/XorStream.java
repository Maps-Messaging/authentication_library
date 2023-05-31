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

package io.mapsmessaging.security.sasl.provider.utils;

public class XorStream {

  private final byte[] key;
  private int keyIndex;

  public XorStream(byte[] key) {
    this.key = key;
    keyIndex = 0;
  }

  public byte[] xorBuffer(byte[] incoming, int offset, int len) {
    byte[] buf = new byte[len];
    int x = offset;
    for (int y = 0; y < buf.length; y++) {
      buf[y] = (byte) (incoming[x] ^ key[keyIndex]);
      keyIndex = (keyIndex + 1) % key.length;
      x++;
    }
    return buf;
  }
}
