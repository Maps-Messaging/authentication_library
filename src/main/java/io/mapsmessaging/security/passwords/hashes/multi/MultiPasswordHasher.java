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

import io.mapsmessaging.security.passwords.PasswordBuffer;
import io.mapsmessaging.security.passwords.PasswordHandler;
import io.mapsmessaging.security.passwords.PasswordHandlerFactory;
import io.mapsmessaging.security.passwords.PasswordHasher;
import io.mapsmessaging.security.util.ArrayHelper;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.List;
import lombok.Getter;

public class MultiPasswordHasher implements PasswordHasher {

  @Getter
  private final List<PasswordHandler> parsers;

  private PasswordBuffer password;

  public MultiPasswordHasher() {
    parsers = new ArrayList<>();
  }

  public MultiPasswordHasher(List<PasswordHandler> list) {
    parsers = new ArrayList<>();
    for (PasswordHandler handler : list) {
      parsers.add(handler.create(new char[0])); // do a copy
    }
    password = new PasswordBuffer(new char[0]);
  }

  public MultiPasswordHasher(char[] pw) {
    parsers = new ArrayList<>();
    int ind = ArrayHelper.indexOf(pw, '$');
    if (ind != -1) {
      password = new PasswordBuffer(ArrayHelper.substring(pw, ind + 1));
      char[][] hashes = ArrayHelper.jsonArrayToCharArrays(password.getHash());
      for (char[] hash : hashes) {
        parsers.add(PasswordHandlerFactory.getInstance().parse(hash));
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
    List<char[]> hashes = new ArrayList<>();
    for (PasswordHandler handler : parsers) {
      int localCost = cost;
      if (cost == 0) {
        localCost = handler.getCost();
      }
      char[] tmpPassword = new char[password.length];
      System.arraycopy(password, 0, tmpPassword, 0, tmpPassword.length);
      char[] hash = handler.transformPassword(tmpPassword, salt, localCost);
      ArrayHelper.clearCharArray(tmpPassword);
      hashes.add(hash);
    }
    return ArrayHelper.appendCharArrays(getName().toCharArray(), "$".toCharArray(),  ArrayHelper.charArraysToJsonArray(hashes));
  }

  @Override
  public byte[] getSalt() {
    return new byte[0];
  }

  @Override
  public char[] getPassword() {
    return password.getHash();
  }

  @Override
  public char[] getFullPasswordHash() {
    return ArrayHelper.appendCharArrays(getName().toCharArray(), "$".toCharArray(), password.getHash());
  }

  @Override
  public String getName() {
    return "Multi";
  }
}