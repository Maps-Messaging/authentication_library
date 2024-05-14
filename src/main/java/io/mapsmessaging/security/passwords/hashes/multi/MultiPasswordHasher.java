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

package io.mapsmessaging.security.passwords.hashes.multi;

import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;
import io.mapsmessaging.security.passwords.PasswordHandler;
import io.mapsmessaging.security.passwords.PasswordHandlerFactory;
import io.mapsmessaging.security.passwords.PasswordHasher;
import io.mapsmessaging.security.util.ArrayHelper;
import java.io.IOException;
import java.lang.reflect.Type;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import lombok.Getter;

public class MultiPasswordHasher implements PasswordHasher {

  @Getter
  private final List<PasswordHandler> parsers;

  private char[] password;

  public MultiPasswordHasher() {
    parsers = new ArrayList<>();
  }

  public MultiPasswordHasher(List<PasswordHandler> list) {
    parsers = new ArrayList<>();
    for (PasswordHandler handler : list) {
      parsers.add(handler.create(new char[0])); // do a copy
    }
    password = new char[0];
  }

  public MultiPasswordHasher(char[] pw) {
    parsers = new ArrayList<>();
    int ind = ArrayHelper.indexOf(pw, '$');
    if (ind != -1) {
      password = ArrayHelper.substring(pw, ind + 1);
      Type listType = new TypeToken<List<String>>() {}.getType();
      String jsonString = new String(password);
      List<String> hashes = new Gson().fromJson(jsonString, listType);
      for (String hash : hashes) {
        parsers.add(PasswordHandlerFactory.getInstance().parse(hash.toCharArray()));
      }
    }
  }

  public void addParser(PasswordHasher passwordHasher) {
    parsers.add(passwordHasher);
  }

  public PasswordHasher create(char[] password) {
    return new MultiPasswordHasher(password);
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
  public char[] transformPassword(char[] password, byte[] salt, int cost)
      throws GeneralSecurityException, IOException {
    List<String> hashes = new ArrayList<>();
    for (PasswordHandler handler : parsers) {
      int localCost = cost;
      if (cost == 0) {
        localCost = handler.getCost();
      }
      char[] tmpPassword = new char[password.length];
      System.arraycopy(password, 0, tmpPassword, 0, tmpPassword.length);
      String hash = new String(handler.transformPassword(tmpPassword, salt, localCost));
      Arrays.fill(tmpPassword, (char)0);
      hashes.add(hash);
    }
    String t = new Gson().toJson(hashes);
    this.password = t.toCharArray();
    return (getName() + "$" + t).toCharArray();
  }

  @Override
  public byte[] getSalt() {
    return new byte[0];
  }

  @Override
  public char[] getPassword() {
    return password;
  }

  @Override
  public char[] getFullPasswordHash() {
    return (getName() + "$" + new String(password)).toCharArray();
  }

  @Override
  public String getName() {
    return "Multi";
  }
}