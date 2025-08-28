/*
 * Copyright [ 2020 - 2024 ] Matthew Buckton
 *  Copyright [ 2024 - 2025 ] MapsMessaging B.V.
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

package io.mapsmessaging.security.access.mapping.store;

import static org.junit.jupiter.api.Assertions.*;

import io.mapsmessaging.security.access.mapping.UserIdMap;
import io.mapsmessaging.security.access.mapping.UserMapParser;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class MapFileStoreTest {

  @Test
  void testLoad(@TempDir Path tempDir) throws IOException {
    Path testFile = tempDir.resolve("testLoad.txt");
    Files.write(testFile, List.of("123e4567-e89b-12d3-a456-426614174000 = authDomain:username"));

    MapFileStore<UserIdMap> store = new MapFileStore<>(testFile.toString());
    List<UserIdMap> entries = store.load(new UserMapParser());

    assertEquals(1, entries.size(), "Should load one UserIdMap entry");
    // Further assertions can be made based on the expected content of the UserIdMap
  }

  @Test
  void testSave(@TempDir Path tempDir) throws IOException {
    Path testFile = tempDir.resolve("testSave.txt");
    MapFileStore<UserIdMap> store = new MapFileStore<>(testFile.toString());
    List<UserIdMap> entries = List.of(new UserIdMap(UUID.randomUUID(), "username", "authDomain"));

    store.save(entries, new UserMapParser());

    List<String> lines = Files.readAllLines(testFile);
    assertFalse(lines.isEmpty(), "File should not be empty after save");
  }

}
