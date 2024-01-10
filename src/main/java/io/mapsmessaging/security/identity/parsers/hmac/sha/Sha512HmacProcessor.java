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

package io.mapsmessaging.security.identity.parsers.hmac.sha;

import io.mapsmessaging.security.identity.parsers.PasswordParser;
import io.mapsmessaging.security.identity.parsers.hmac.HmacData;
import io.mapsmessaging.security.identity.parsers.sha.UnixSha512PasswordParser;

public class Sha512HmacProcessor extends ShaHmacProcessor {

  public Sha512HmacProcessor() {
    this("SHA-512::");
  }

  public Sha512HmacProcessor(String password) {
    super(new HmacData(password));
  }

  @Override
  public PasswordParser create(String password) {
    return new UnixSha512PasswordParser(password);
  }

  @Override
  public String getName() {
    return "SHA-512";
  }
}
