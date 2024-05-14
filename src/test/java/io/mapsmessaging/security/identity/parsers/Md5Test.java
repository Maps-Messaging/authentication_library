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

import java.io.IOException;
import java.security.GeneralSecurityException;
import org.junit.jupiter.api.Test;

class Md5Test extends BaseHashFunctions {

  @Test
  void checkMd5Hash() throws GeneralSecurityException, IOException {
    testHashing("$apr1$po9cazbx$JG5SMaTSVYrtFlYQb821M.", "This is an md5 password".toCharArray());
  }

  @Test
  void checkMd5HashWithBadPassword() throws GeneralSecurityException, IOException {
    testHashing("$apr1$po9cazbx$JG5SMaTSVYrtFlYQb821M.", "This is wrong".toCharArray(), false);
  }

}
