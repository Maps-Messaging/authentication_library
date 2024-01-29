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

package io.mapsmessaging.security.uuid;

import static org.junit.jupiter.api.Assertions.*;

import java.util.UUID;
import org.junit.jupiter.api.Test;

public class UuidGeneratorTest {

  @Test
  void testGenerateWithDefaultVersion() {
    UUID uuid = UuidGenerator.generate();
    assertNotNull(uuid, "Generated UUID should not be null for default version");
    // Additional checks can be added based on the expected behavior of the default version
  }

  @Test
  void testGenerateWithUnsupportedVersion() {
    UUID uuid = UuidGenerator.generate(999); // An unsupported version
    assertNotNull(uuid, "Generated UUID should not be null for unsupported version");
  }
}



