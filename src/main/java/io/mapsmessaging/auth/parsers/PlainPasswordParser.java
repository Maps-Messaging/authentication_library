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

package io.mapsmessaging.auth.parsers;

import io.mapsmessaging.auth.PasswordParser;

public class PlainPasswordParser implements PasswordParser {
  private final String password;

  public PlainPasswordParser(){
    password = "";
  }

  public PlainPasswordParser(String password){
    this.password = password;
  }

  public PasswordParser create(String password){
    return new PlainPasswordParser(password);
  }
  @Override
  public String getKey() {
    return "";
  }

  @Override
  public boolean hasSalt() {
    return false;
  }

  @Override
  public char[] getSalt() {
    return new char[0];
  }

  @Override
  public char[] getPassword() {
    return password.toCharArray();
  }

  @Override
  public char[] getFullPasswordHash() {
    return password.toCharArray();
  }

  @Override
  public String getName() {
    return "PLAIN";
  }
}
