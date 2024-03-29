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

package io.mapsmessaging.security.passwords.hashes.pbkdf2;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import org.bouncycastle.crypto.digests.SHA3Digest;
import org.bouncycastle.crypto.generators.PKCS5S2ParametersGenerator;
import org.bouncycastle.crypto.params.KeyParameter;

public abstract class Pbkdf2Sha3PasswordHasher extends Pbkdf2PasswordHasher {

  protected Pbkdf2Sha3PasswordHasher(String password) {
    super(password);
  }

  @Override
  public byte[] transformPassword(byte[] password, byte[] salt, int cost) {
    PKCS5S2ParametersGenerator generator =
        new PKCS5S2ParametersGenerator((new SHA3Digest(getHashByteSize() * 8)));
    generator.init(password, salt, cost);
    byte[] hash =
        ((KeyParameter) generator.generateDerivedParameters(getHashByteSize() * 8)).getKey();
    return (getKey()
            + "$"
            + cost
            + "$"
            + Base64.getEncoder().encodeToString(salt)
            + "$"
            + Base64.getEncoder().encodeToString(hash))
        .getBytes(StandardCharsets.UTF_8);
  }
}
