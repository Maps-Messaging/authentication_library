/*
 *
 *  Copyright [ 2020 - 2024 ] [Matthew Buckton]
 *  Copyright [ 2024 - 2025 ] [Maps Messaging B.V.]
 *
 *   Licensed under the Apache License, Version 2.0 (the "License");
 *   you may not use this file except in compliance with the License.
 *   You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */

package io.mapsmessaging.security.identity.impl.external;

import com.auth0.jwt.interfaces.DecodedJWT;
import io.mapsmessaging.security.passwords.PasswordBuffer;
import io.mapsmessaging.security.passwords.PasswordHasher;
import lombok.Getter;

public abstract class JwtPasswordHasher extends PasswordHasher {

  @Getter
  protected DecodedJWT jwt;
  protected PasswordBuffer computedPassword;

  @Override
  public PasswordHasher create(char[] password) {
    return null;
  }

  @Override
  public String getKey() {
    return null;
  }

  @Override
  public boolean hasSalt() {
    return false;
  }

  @Override
  public byte[] getSalt() {
    return new byte[0];
  }

  @Override
  public PasswordBuffer getPassword() {
    if(computedPassword == null) {
      return new PasswordBuffer(new char[0]);
    }
    return computedPassword;
  }

  @Override
  public char[] getFullPasswordHash() {
    if(computedPassword == null){
      return new char[0];
    }
    return computedPassword.getHash();
  }
}
