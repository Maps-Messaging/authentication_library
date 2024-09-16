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
import static org.junit.jupiter.params.provider.Arguments.arguments;

import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

public class UuidGeneratorTest {

  private static List<Arguments> randomVersions() {
    List<Arguments> arguments = new ArrayList<>();
    for (RandomVersions version : RandomVersions.values()) {
      arguments.add(arguments(version));
    }
    return arguments;
  }

  private static List<Arguments> namedVersions() {
    List<Arguments> arguments = new ArrayList<>();
    for (NamedVersions version : NamedVersions.values()) {
      arguments.add(arguments(version));
    }
    return arguments;
  }

  @Test
  void testGenerateRandomWithDefaultVersion() {
    UUID uuid = UuidGenerator.getInstance().generate();
    assertNotNull(uuid, "Generated UUID should not be null for default version");
    // Additional checks can be added based on the expected behavior of the default version
  }

  @ParameterizedTest
  @MethodSource("randomVersions")
  void testGenerateRandomWithAllVersion(RandomVersions version) {
    UUID uuid = UuidGenerator.getInstance().generate(version);
    UUID uuid2 = UuidGenerator.getInstance().generate(version);
    assertNotNull(uuid, "Generated UUID should not be null for supported version");
    assertNotEquals(uuid, uuid2);
  }

  @ParameterizedTest
  @MethodSource("namedVersions")
  void testGenerateNamedithAllVersion(NamedVersions version) throws NoSuchAlgorithmException {
    UUID rootUuid = UuidGenerator.getInstance().generate(RandomVersions.TIME_EPOCH);
    UUID named = UuidGenerator.getInstance().generate(version, rootUuid, "/test/namespace");
    UUID named2 = UuidGenerator.getInstance().generate(version, rootUuid, "/test/namespace");
    assertNotNull(named, "Generated UUID should not be null for supported named version");
    assertEquals(named, named2);
    UUID named3 = UuidGenerator.getInstance().generate(version, rootUuid, "/test/namespace1");
    assertNotEquals(named, named3);
  }

}



