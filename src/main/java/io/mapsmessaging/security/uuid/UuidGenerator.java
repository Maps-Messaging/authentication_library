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

package io.mapsmessaging.security.uuid;

import com.fasterxml.uuid.Generators;
import com.fasterxml.uuid.impl.NameBasedGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;

@SuppressWarnings("java:S6548") // yes it is a singleton
public class UuidGenerator {

  private static class Holder {
    static final UuidGenerator INSTANCE = new UuidGenerator();
  }

  public static UuidGenerator getInstance() {
    return UuidGenerator.Holder.INSTANCE;
  }

  private final RandomVersions uuidDefaultVersion;
  private final Map<UUID, NameBasedGenerator> namedGeneratorMap;

  @SuppressWarnings("java:S3824") // the getInstance throws an exception. It is better for it to be handled like this
  public UUID generate(NamedVersions namedVersions, UUID namespaceUuid, String namespace) throws NoSuchAlgorithmException {
    NameBasedGenerator namespaceGenerator = namedGeneratorMap.get(namespaceUuid);
    if (namespaceGenerator == null) {
      MessageDigest messageDigest = MessageDigest.getInstance(namedVersions.getDigestAlgorithm());
      namespaceGenerator = Generators.nameBasedGenerator(namespaceUuid, messageDigest);
      namedGeneratorMap.put(namespaceUuid, namespaceGenerator);
    }
    return namespaceGenerator.generate(namespace);
  }

  public UUID generate() {
    return generate(uuidDefaultVersion);
  }

  public UUID generate(RandomVersions version) {
    switch (version) {
      case TIME:
        return Generators.timeBasedGenerator().generate();
      case RANDOM:
        return UUID.randomUUID();
      case TIME_REORDERED:
        return Generators.timeBasedReorderedGenerator().generate();
      case TIME_EPOCH:
      default:
        return Generators.timeBasedEpochGenerator().generate();
    }
  }

  private UuidGenerator() {
    namedGeneratorMap = new LinkedHashMap<>();
    int val = 7;
    String version = System.getProperty("UUID_VERSION", "7");
    if (version != null) {
      try {
        val = Integer.parseInt(version);
      } catch (NumberFormatException th) {
        // ignore
      }
    }
    RandomVersions defaultVersion = RandomVersions.TIME_EPOCH;
    for (RandomVersions versions : RandomVersions.values()) {
      if (versions.getVersion() == val) {
        defaultVersion = versions;
      }
    }
    uuidDefaultVersion = defaultVersion;
  }
}
