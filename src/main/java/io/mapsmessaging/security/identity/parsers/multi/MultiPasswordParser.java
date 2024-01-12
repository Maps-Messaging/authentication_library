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

package io.mapsmessaging.security.identity.parsers.multi;

import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;
import io.mapsmessaging.security.identity.parsers.PasswordParser;
import io.mapsmessaging.security.identity.parsers.PasswordParserFactory;
import java.lang.reflect.Type;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import lombok.Getter;

public class MultiPasswordParser implements PasswordParser {

  @Getter
  private final List<PasswordParser> parsers;

  private String password;

  public MultiPasswordParser() {
    parsers = new ArrayList<>();
  }

  public MultiPasswordParser(List<PasswordParser> list) {
    parsers = new ArrayList<>();
    for (PasswordParser parser : list) {
      parsers.add(parser.create("")); // do a copy
    }
    password = "";
  }

  public MultiPasswordParser(String password) {
    parsers = new ArrayList<>();
    int ind = password.indexOf("$");
    if (ind != -1) {
      this.password = password.substring(ind + 1);

      Type listType = new TypeToken<List<String>>() {
      }.getType();
      List<String> hashes = new Gson().fromJson(this.password, listType);
      for (String hash : hashes) {
        parsers.add(PasswordParserFactory.getInstance().parse(hash));
      }
    }
  }

  public void addParser(PasswordParser passwordParser) {
    parsers.add(passwordParser);
  }

  public PasswordParser create(String password) {
    return new MultiPasswordParser(parsers);
  }

  @Override
  public String getKey() {
    return "Multi";
  }

  @Override
  public boolean hasSalt() {
    return false;
  }

  @Override
  public byte[] transformPassword(byte[] password, byte[] salt, int cost) {
    List<String> hashes = new ArrayList<>();
    for (PasswordParser parser : parsers) {
      int localCost = cost;
      if (cost == 0) {
        localCost = parser.getCost();
      }
      hashes.add(new String(parser.transformPassword(password, salt, localCost)));
    }
    this.password = new Gson().toJson(hashes);
    return (getName() + "$" + this.password).getBytes(StandardCharsets.UTF_8);
  }

  @Override
  public byte[] getSalt() {
    return new byte[0];
  }

  @Override
  public byte[] getPassword() {
    return password.getBytes(StandardCharsets.UTF_8);
  }

  @Override
  public char[] getFullPasswordHash() {
    return (getName() + "$" + password).toCharArray();
  }

  @Override
  public String getName() {
    return "Multi";
  }
}