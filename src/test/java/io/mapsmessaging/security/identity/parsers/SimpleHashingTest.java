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
import java.io.*;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

public class SimpleHashingTest {

  private static final char[] PASSWORD_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+=-\\|][{};:\"'/?.>,<`~".toCharArray();

  @Test
  void testHashAndValidate(){
    String password = generatePassword(16);
    for(PasswordParser base: PasswordParserFactory.getInstance().getPasswordParsers()){
      String salt = PasswordGenerator.generateSalt(16);
      PasswordParser parser = base.create("");
      byte[] hash = parser.computeHash(password.getBytes(), salt.getBytes(), parser.getCost());
      String storeHash = new String(hash);
      PasswordParser lookup = PasswordParserFactory.getInstance().parse(storeHash);
      Assertions.assertEquals(lookup.getClass().toString(), parser.getClass().toString());
      byte[] computed = lookup.computeHash(password.getBytes(), lookup.getSalt(), lookup.getCost());
      Assertions.assertArrayEquals(hash, computed);
    }
  }

  @Test
  void testFileLoadAndParse() throws IOException {
    FileOutputStream fileOutputStream = new FileOutputStream("hash.txt", false);
    String password = generatePassword(16);
    for(PasswordParser base: PasswordParserFactory.getInstance().getPasswordParsers()){
      String salt = PasswordGenerator.generateSalt(16);
      PasswordParser parser = base.create("");
      byte[] hash = parser.computeHash(password.getBytes(), salt.getBytes(), parser.getCost());
      String storeHash = new String(hash);
      fileOutputStream.write(hash);
      fileOutputStream.write("\n".getBytes());
    }
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
    for(String hash:hashes){
      PasswordParser lookup = PasswordParserFactory.getInstance().parse(hash);
      byte[] computed = lookup.computeHash(password.getBytes(), lookup.getSalt(), lookup.getCost());
      Assertions.assertArrayEquals(hash.getBytes(), computed);

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
