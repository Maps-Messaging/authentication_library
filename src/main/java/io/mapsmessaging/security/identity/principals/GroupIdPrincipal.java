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

package io.mapsmessaging.security.identity.principals;

import io.mapsmessaging.security.access.mapping.GroupIdMap;
import java.security.Principal;
import java.util.List;
import lombok.Getter;

public class GroupIdPrincipal implements Principal {

  @Getter
  private final List<GroupIdMap> groupIds;

  public GroupIdPrincipal(List<GroupIdMap> groupIds) {
    this.groupIds = groupIds;
  }

  @Override
  public String getName() {
    return "GroupIds";
  }

  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder("Group Ids:");
    for (GroupIdMap groupId : groupIds) {
      sb.append("\n\t").append(groupId.toString());
    }
    return sb.toString();
  }
}
