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

package io.mapsmessaging.security.identity.parsers;

import io.mapsmessaging.security.identity.PasswordGenerator;
import io.mapsmessaging.security.passwords.PasswordHasher;
import io.mapsmessaging.security.passwords.hashes.sha.UnixSha256PasswordHasher;
import io.mapsmessaging.security.passwords.hashes.sha.UnixSha512PasswordHasher;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

class UnixShaTest extends BaseHashFunctions {

  @Test
  void testCreateAndTest512() {
    String password = "This is a long password that needs to be hashed";
    String salt = PasswordGenerator.generateSalt(12);
    PasswordHasher passwordHasher = new UnixSha512PasswordHasher();
    byte[] hash =
        passwordHasher.transformPassword(
            password.getBytes(StandardCharsets.UTF_8), salt.getBytes(StandardCharsets.UTF_8), 5000);

    PasswordHasher passwordCheck = new UnixSha512PasswordHasher(new String(hash));
    byte[] check =
        passwordCheck.transformPassword(
            password.getBytes(StandardCharsets.UTF_8), passwordCheck.getSalt(), 5000);
    Assertions.assertArrayEquals(hash, check);
  }

  @Test
  void testCreateAndTest256() {
    String password = "This is a long password that needs to be hashed";
    String salt = PasswordGenerator.generateSalt(12);
    PasswordHasher passwordHasher = new UnixSha256PasswordHasher();
    byte[] hash =
        passwordHasher.transformPassword(
            password.getBytes(StandardCharsets.UTF_8), salt.getBytes(StandardCharsets.UTF_8), 5000);

    PasswordHasher passwordCheck = new UnixSha256PasswordHasher(new String(hash));
    byte[] check =
        passwordCheck.transformPassword(
            password.getBytes(StandardCharsets.UTF_8), passwordCheck.getSalt(), 5000);
    Assertions.assertArrayEquals(hash, check);
  }

  @Test
  void checkSha512Hash() {
    testHashing("$6$DVW4laGf$QwTuOOtd.1G3u2fs8d5/OtcQ73qTbwA.oAC1XWTmkkjrvDLEJ2WweTcBdxRkzfjQVfZCw3OVVBAMsIGMkH3On/", "onewordpassword");
  }

  @Test
  void checkSha512HashWithSpaces() {
    testHashing("$6$fiizFR2o$IQNwJXIXyQEL1ikJqvFrYGMBRiTBLnjY0OFfty9O472tWdJOY6czvUpuSDJQpzojQkLqNlP6devotoSBQCp//1", "this has spaces");
  }

  @Test
  void checkSha512HashBadPassword() {
    testHashing("$6$fiizFR2o$IQNwJXIXyQEL1ikJqvFrYGMBRiTBLnjY0OFfty9O472tWdJOY6czvUpuSDJQpzojQkLqNlP6devotoSBQCp//1", "just wrong", false);
  }
}
