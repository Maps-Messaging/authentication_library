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

package io.mapsmessaging.security.cipher;

import io.mapsmessaging.security.certificates.BaseCertificateTest;
import java.security.SecureRandom;
import java.util.Arrays;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

class BufferCipherTest extends BaseCertificateTest {

  void setupStore(String type) throws Exception {
    super.setUp(type, "file");
    addMultiCertificates(certificateManager);
  }

  @ParameterizedTest
  @MethodSource("knownTypes")
  void encryptTest(String type) throws Exception {
    setupStore(type);
    BufferCipher bufferCipher = new BufferCipher(certificateManager);
    byte[] buffer = new byte[100];
    for (int x = 0; x < buffer.length; x++) {
      buffer[x] = (byte) (x & 0x7f);
    }
    byte[] encrypted = bufferCipher.encrypt(TEST_ALIAS + "_1", buffer);
    Assertions.assertFalse(isEqual(buffer, encrypted));
    byte[] plain =
        bufferCipher.decrypt(
            TEST_ALIAS + "_1", encrypted, (new String(KEY_PASSWORD) + "_1").toCharArray());
    Assertions.assertFalse(isEqual(plain, encrypted));
    Assertions.assertArrayEquals(buffer, plain);
  }

  @ParameterizedTest
  @MethodSource("knownTypes")
  void encryptRandomSizeTest(String type) throws Exception {
    setupStore(type);
    SecureRandom secureRandom = new SecureRandom();
    BufferCipher bufferCipher = new BufferCipher(certificateManager);
    for (int x = 0; x < 10; x++) {
      byte[] buffer = new byte[10 + Math.abs(secureRandom.nextInt(10240))];
      secureRandom.nextBytes(buffer);
      byte[] encrypted = bufferCipher.encrypt(TEST_ALIAS + "_1", buffer);
      Assertions.assertFalse(isEqual(buffer, encrypted));
      byte[] plain =
          bufferCipher.decrypt(
              TEST_ALIAS + "_1", encrypted, (new String(KEY_PASSWORD) + "_1").toCharArray());
      Assertions.assertFalse(isEqual(plain, encrypted));
      Assertions.assertArrayEquals(buffer, plain);
    }
  }

  private boolean isEqual(byte[] buffer1, byte[] buffer2) {
    return Arrays.equals(buffer1, buffer2);
  }
}
