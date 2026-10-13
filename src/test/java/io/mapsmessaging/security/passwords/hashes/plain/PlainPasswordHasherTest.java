/*
 * Copyright [ 2020 - 2024 ] Matthew Buckton
 *  Copyright [ 2024 - 2026 ] MapsMessaging B.V.
 *
 *  Licensed under the Apache License, Version 2.0 with the Commons Clause
 *  (the "License"); you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at:
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *      https://commonsclause.com/
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 *
 */

package io.mapsmessaging.security.passwords.hashes.plain;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;

class PlainPasswordHasherTest {

  @ParameterizedTest
  @ValueSource(strings = {"Abc$Def123!", "$secret", "secret$", "$$", "a$b$c", "UNKNOWN$secret", "PLAIN", "päss$✓", ""})
  void preserves_unprefixed_password(String value) {
    PlainPasswordHasher hasher = new PlainPasswordHasher(value.toCharArray());

    assertArrayEquals(value.toCharArray(), hasher.getPassword().getHash());
    assertTrue(hasher.matches(value.toCharArray()));
    assertFalse(hasher.matches((value + "wrong").toCharArray()));
  }

  @ParameterizedTest
  @CsvSource(value = {
      "PLAIN$Abc$Def123!|Abc$Def123!",
      "PLAIN$$Abc$|$Abc$",
      "PLAIN$secret$|secret$",
      "PLAIN$PLAIN$secret|PLAIN$secret",
      "plain$a$b|a$b",
      "PlAiN$a$b|a$b",
      "PLAIN$|''"
  }, delimiter = '|')
  void removes_only_recognised_plain_prefix(String encoded, String expected) {
    PlainPasswordHasher hasher = new PlainPasswordHasher(encoded.toCharArray());

    assertArrayEquals(expected.toCharArray(), hasher.getPassword().getHash());
    assertArrayEquals(("PLAIN$" + expected).toCharArray(), hasher.getFullPasswordHash());
  }

  @ParameterizedTest
  @ValueSource(strings = {"Abc$Def123!", "$secret", "secret$", "$$", "a$b$c", ""})
  void round_trips_encoded_password_without_losing_dollars(String value) {
    PlainPasswordHasher original = new PlainPasswordHasher(value.toCharArray());
    PlainPasswordHasher restored = (PlainPasswordHasher) original.create(original.getFullPasswordHash());

    assertArrayEquals(value.toCharArray(), restored.getPassword().getHash());
    assertTrue(restored.matches(value.toCharArray()));
  }

  @ParameterizedTest
  @ValueSource(strings = {"Abc$Def123!", "PLAIN$Abc$Def123!"})
  void clears_constructor_input_after_copying(String value) {
    char[] input = value.toCharArray();
    char[] expected = new char[input.length];

    PlainPasswordHasher hasher = new PlainPasswordHasher(input);

    assertArrayEquals(expected, input);
    assertTrue(hasher.matches("Abc$Def123!".toCharArray()));
  }
}
