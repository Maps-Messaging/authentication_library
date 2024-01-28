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

package io.mapsmessaging.security.identity.impl.unix;


import io.mapsmessaging.security.identity.GroupEntry;
import io.mapsmessaging.security.identity.IllegalFormatException;
import java.util.Collections;
import java.util.StringTokenizer;
import lombok.Getter;

@Getter
public class GroupFileEntry extends GroupEntry {

  private final int groupId;

  public GroupFileEntry(String line) throws IllegalFormatException {
    super();
    int index = line.indexOf(":");
    if (index == -1) {
      throw new IllegalFormatException("Expected format to be a : delimited list");
    }
    StringTokenizer stringTokenizer = new StringTokenizer(line, ":");
    name = stringTokenizer.nextElement().toString(); //
    stringTokenizer.nextElement();// drop
    groupId = Integer.parseInt(stringTokenizer.nextElement().toString().trim());
    if (stringTokenizer.hasMoreElements()) {
      String groups = stringTokenizer.nextElement().toString();
      if (!groups.trim().isEmpty()) {
        Collections.addAll(userSet, groups.split(","));
      }
    }
  }

}
