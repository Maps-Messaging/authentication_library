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
import io.mapsmessaging.security.passwords.PasswordHandler;
import io.mapsmessaging.security.passwords.PasswordHandlerFactory;
import io.mapsmessaging.security.passwords.PasswordHasher;
import io.mapsmessaging.security.passwords.hashes.multi.MultiPasswordHasher;
import java.io.BufferedReader;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

public class SimpleHashingTest {

  private static final char[] PASSWORD_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+=-\\|][{};:\"'/?.>,<`~".toCharArray();

  private static Stream<PasswordHandler> knownParsers() {
    return PasswordHandlerFactory.getInstance().getPasswordHashers().stream()
        .filter(
            passwordParser ->
                !(passwordParser instanceof MultiPasswordHasher)
                    && (passwordParser instanceof PasswordHasher));
  }

  @Test
  void testMultiParser() {
    String password = generatePassword(16);
    String salt = PasswordGenerator.generateSalt(16);

    List<PasswordHandler> parsers = knownParsers().collect(Collectors.toList());
    MultiPasswordHasher parser = new MultiPasswordHasher(parsers);
    byte[] hash =
        parser.transformPassword(
            password.getBytes(StandardCharsets.UTF_8), salt.getBytes(StandardCharsets.UTF_8), 0);
    String storeHash = new String(hash);
    PasswordHandler lookup = PasswordHandlerFactory.getInstance().parse(new String(hash));
    Assertions.assertEquals(lookup.getClass().toString(), parser.getClass().toString());
    byte[] computed =
        lookup.transformPassword(
            generatePassword(16).getBytes(StandardCharsets.UTF_8),
            lookup.getSalt(),
            lookup.getCost());
    String computedString = new String(computed);
    Assertions.assertNotEquals(storeHash, computedString);
  }

  @ParameterizedTest
  @MethodSource("knownParsers")
  void testHashAndValidateBadPassword(PasswordHasher base) {
    String password = generatePassword(16);
    String salt = PasswordGenerator.generateSalt(16);
    PasswordHandler parser = base.create("");
    byte[] hash =
        parser.transformPassword(
            password.getBytes(StandardCharsets.UTF_8),
            salt.getBytes(StandardCharsets.UTF_8),
            parser.getCost());
    String storeHash = new String(hash);
    PasswordHandler lookup = PasswordHandlerFactory.getInstance().parse(storeHash);
    Assertions.assertEquals(lookup.getClass().toString(), parser.getClass().toString());
    byte[] computed =
        lookup.transformPassword(
            generatePassword(16).getBytes(StandardCharsets.UTF_8),
            lookup.getSalt(),
            lookup.getCost());
    String computedString = new String(computed);
    Assertions.assertNotEquals(storeHash, computedString);
  }

  @ParameterizedTest
  @MethodSource("knownParsers")
  void testHashAndValidate(PasswordHasher base) {
    String password = generatePassword(16);
    String salt = PasswordGenerator.generateSalt(16);
    PasswordHandler parser = base.create("");
    byte[] hash =
        parser.transformPassword(
            password.getBytes(StandardCharsets.UTF_8),
            salt.getBytes(StandardCharsets.UTF_8),
            parser.getCost());
    String storeHash = new String(hash);
    PasswordHandler lookup = PasswordHandlerFactory.getInstance().parse(storeHash);
    Assertions.assertEquals(lookup.getClass().toString(), parser.getClass().toString());
    byte[] computed =
        lookup.transformPassword(
            password.getBytes(StandardCharsets.UTF_8), lookup.getSalt(), lookup.getCost());
    String computedString = new String(computed);
    Assertions.assertEquals(storeHash, computedString);
  }

  @ParameterizedTest
  @MethodSource("knownParsers")
  void testFileLoadAndParse(PasswordHasher base) throws IOException {
    FileOutputStream fileOutputStream = new FileOutputStream("hash.txt", false);
    String password = generatePassword(16);
    String salt = PasswordGenerator.generateSalt(16);
    PasswordHandler parser = base.create("");
    byte[] hash =
        parser.transformPassword(
            password.getBytes(StandardCharsets.UTF_8),
            salt.getBytes(StandardCharsets.UTF_8),
            parser.getCost());
    String storeHash = new String(hash);
    fileOutputStream.write(hash);
    fileOutputStream.write("\n".getBytes(StandardCharsets.UTF_8));
    fileOutputStream.close();


    List<String> hashes = new ArrayList<>();
    try (BufferedReader reader = new BufferedReader(new FileReader("hash.txt"))) {
      String line;
      while ((line = reader.readLine()) != null) {
        hashes.add(line);
      }
    } catch (IOException e) {
      e.printStackTrace();
    }
    for (String received : hashes) {
      PasswordHandler lookup = PasswordHandlerFactory.getInstance().parse(received);
      byte[] computed =
          lookup.transformPassword(
              password.getBytes(StandardCharsets.UTF_8), lookup.getSalt(), lookup.getCost());
      Assertions.assertArrayEquals(received.getBytes(StandardCharsets.UTF_8), computed);
    }
  }

  private String generatePassword(int len){
    Random random = new Random();
    StringBuilder sb = new StringBuilder();
    int x=0;
    while(x<len){
      int y = Math.abs(random.nextInt(PASSWORD_CHARS.length));
      sb.append(PASSWORD_CHARS[y]);
      x++;
    }
    return sb.toString();
  }

}
