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

package io.mapsmessaging.security.passwords;

import io.mapsmessaging.security.util.ArrayHelper;
import java.nio.ByteBuffer;

public class PasswordBuffer {
  private final ByteBuffer buffer;
  private int end =0;

  public PasswordBuffer(char[] hash) {
    byte[] buf = ArrayHelper.charArrayToByteArray(hash);
    ByteBuffer tmp = ByteBuffer.allocateDirect(buf.length);
    tmp.put(buf);
    tmp.flip();
    end = buf.length;
    buffer = tmp.asReadOnlyBuffer();
  }

  public PasswordBuffer(byte[] buf) {
    ByteBuffer tmp = ByteBuffer.allocateDirect(buf.length);
    tmp.put(buf);
    tmp.flip();
    end = buf.length;
    buffer = tmp.asReadOnlyBuffer();
  }

  public void clear(){
    byte[] buf = buffer.array();
    ArrayHelper.clearByteArray(buf);
    buffer.clear();
    buffer.put(buf);
  }

  public synchronized byte[] getBytes(){
    byte[] tmp = new byte[end];
    buffer.position(0);
    buffer.get(tmp);
    buffer.flip();
    return tmp;
  }

  public char[] getHash() {
    return ArrayHelper.byteArrayToCharArray(getBytes());
  }
}
