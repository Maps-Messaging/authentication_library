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

package io.mapsmessaging.security.passwords;

import io.mapsmessaging.security.util.ArrayHelper;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.Arrays;

public abstract class PasswordHandler {

  public boolean matches(char[] attemptedPassword) throws GeneralSecurityException, IOException {
    char[] remoteHash = transformPassword(attemptedPassword, getSalt(), getCost());
    char[] localHash = getFullPasswordHash();
    boolean result = Arrays.equals(remoteHash, localHash);
    ArrayHelper.clearCharArray(localHash);
    return result;
  }

  public int getCost() {
    return 0;
  }

  public abstract String getName();

  public abstract char[] transformPassword(char[] password, byte[] salt, int cost) throws GeneralSecurityException, IOException;

  public abstract PasswordHandler create(char[] password);

  public abstract String getKey();

  public abstract boolean hasSalt();

  public abstract byte[] getSalt();

  public abstract PasswordBuffer getPassword() throws GeneralSecurityException, IOException;

  public abstract char[] getFullPasswordHash();

}
