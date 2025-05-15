/*
 *
 *  Copyright [ 2020 - 2024 ] [Matthew Buckton]
 *  Copyright [ 2024 - 2025 ] [Maps Messaging B.V.]
 *
 *   Licensed under the Apache License, Version 2.0 (the "License");
 *   you may not use this file except in compliance with the License.
 *   You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */

package io.mapsmessaging.security.identity.impl.apache;

import io.mapsmessaging.security.identity.GroupEntry;
import io.mapsmessaging.security.identity.IllegalFormatException;
import java.util.StringTokenizer;

public class HtGroupEntry extends GroupEntry {

  public HtGroupEntry(String line) throws IllegalFormatException {
    super();
    if (!line.endsWith(":") && !line.contains(":")) {
      line = line + ":";
    }
    int index = line.indexOf(":");
    if (index == -1) {
      throw new IllegalFormatException("Expected format, groupName: user name list");
    }
    super.name = line.substring(0, index);
    String userList = line.substring(index + 1);
    StringTokenizer stringTokenizer = new StringTokenizer(userList, " ");
    while (stringTokenizer.hasMoreElements()) {
      String user = stringTokenizer.nextElement().toString().trim();
      userSet.add(user);
    }
  }

}
