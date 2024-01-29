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

import com.fasterxml.uuid.Generators;
import java.util.UUID;
import lombok.Getter;

public class UuidGenerator {

  @Getter
  public enum VERSIONS{
    TIME(1),
    RANDOM(4),
    TIME_REORDERED(6),
    TIME_EPOCH(7);

    private final int version;

    VERSIONS(int version){
      this.version = version;
    }

  }

  static {
    int val = 7;
    String version = System.getProperty("UUID_VERSION");
    if (version != null) {
      try {
        val = Integer.parseInt(version);
      } catch (Throwable th) {
        // ignore
      }
    }
    VERSIONS defaultVersion = VERSIONS.TIME_EPOCH;
    for(VERSIONS versions: VERSIONS.values()){
      if(versions.getVersion() == val){
        defaultVersion = versions;
      }
    }
    UUID_VERSION = defaultVersion;
  }

  private static final VERSIONS UUID_VERSION;

  public static UUID generate() {
    return generate(UUID_VERSION);
  }

  public static UUID generate(VERSIONS version){
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
  }
}
