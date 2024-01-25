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

package io.mapsmessaging.security.access.mapping;

import java.util.UUID;

public class GroupMapParser extends MapParser<GroupIdMap> {

  public GroupMapParser() {
    super();
  }

  @Override
  protected GroupIdMap createMapping(String identifier) {
    String[] keyValue = identifier.split("=");
    UUID uuid = UUID.fromString(keyValue[0].trim());
    String[] groups = keyValue[1].split(":");
    String authDomain = groups[0];
    String groupName = groups[1];
    return new GroupIdMap(uuid, groupName, authDomain);
  }
}
