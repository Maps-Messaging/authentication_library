/*
 * Copyright [ 2020 - 2023 ] [Matthew Buckton]
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
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class GroupMapParser extends MapParser<GroupIdMap> {

  private final Pattern IDENTIFIER_PATTERN =
      Pattern.compile("^([a-fA-F0-9-]+)\\s*=\\s*([^:]+):([^\\[\\]]+)(?:\\[([^\\[\\]]+)\\])?$");

  public GroupMapParser() {
    super();
  }

  @Override
  protected GroupIdMap createMapping(String identifier) {
    Matcher matcher = IDENTIFIER_PATTERN.matcher(identifier);
    if (matcher.matches()) {
      UUID uuid = UUID.fromString(matcher.group(1));
      String authDomain = matcher.group(2);
      String groupName = matcher.group(3);
      return new GroupIdMap(uuid, groupName, authDomain);
    }
    throw new IllegalArgumentException("Invalid identifier format: " + identifier);
  }
}
