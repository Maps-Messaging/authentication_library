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

package io.mapsmessaging.security.identity;

import java.util.Set;
import java.util.TreeSet;
import lombok.Getter;

public class GroupEntry implements Comparable<GroupEntry>{

  protected final Set<String> userSet;
  @Getter
  protected String name;

  public GroupEntry(){
    userSet = new TreeSet<>();
  }

  public GroupEntry(String name){
    this.name = name;
    userSet = new TreeSet<>();
  }

  public GroupEntry(String name, Set<String> userSet){
    this.name = name;
    this.userSet = userSet;
  }


  public boolean isInGroup(String user){
    return userSet.contains(user);
  }

  @Override
  public int compareTo(GroupEntry o) {
    return name.compareTo(o.name);
  }
}
