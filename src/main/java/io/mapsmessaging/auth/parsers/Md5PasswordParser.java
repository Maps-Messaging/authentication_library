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

public class Md5PasswordParser implements PasswordParser {

  private final String password;
  private final String salt;

  public Md5PasswordParser(){
    password = "";
    salt = "";
  }

  protected Md5PasswordParser(String password){
    String sub = password.substring(getKey().length());
    int split = sub.indexOf("$");
    String pw="";
    String sl = "";
    if(split != -1){
      sl = sub.substring(0, split);
      pw = sub.substring(split+1);
    }
    this.password = pw;
    this.salt = sl;
  }

  public PasswordParser create(String password){
    return new Md5PasswordParser(password);
  }
  @Override
  public String getKey() {
    return "$apr1$";
  }

  @Override
  public boolean hasSalt() {
    return salt.length() > 0;
  }

  @Override
  public char[] getSalt() {
    return salt.toCharArray();
  }

  @Override
  public char[] getPassword() {
    return password.toCharArray();
  }

  @Override
  public char[] getFullPasswordHash() {
    return (getKey()+salt+"$" + password).toCharArray();
  }

  @Override
  public String getName() {
    return "MD5";
  }
}
