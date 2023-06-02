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

import com.sun.security.auth.UserPrincipal;
import io.mapsmessaging.security.identity.parsers.PasswordParser;
import java.security.Principal;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import javax.security.auth.Subject;
import lombok.Getter;

public class IdentityEntry {

  @Getter
  protected String username;

  @Getter
  protected PasswordParser passwordParser;

  @Getter
  protected String password;

  protected final Map<String, GroupEntry> groupList = new LinkedHashMap<>();

  public boolean isInGroup(String group){
    return groupList.containsKey(group);
  }

  public void addGroup(GroupEntry group){
    groupList.put(group.name, group);
  }

  public void clearGroups(){
    groupList.clear();
  }

  public List<GroupEntry> getGroups(){
    return new ArrayList<>(groupList.values());
  }

  public Subject getSubject(){
    return new Subject(true, getPrincipals(), new TreeSet<>(), new TreeSet<>());
  }

  protected Set<Principal> getPrincipals(){
    Set<Principal> principals = new HashSet<>();
    principals.add(new UserPrincipal(username));


    for(GroupEntry group:groupList.values()){
      principals.add(new GroupPrincipal(group.getName()));
    }
    return principals;
  }

  @Override
  public String toString() {
    return username + ":" + password;
  }

  static class GroupPrincipal implements Principal {
    private final String name;

    GroupPrincipal(String name) {
      this.name = name;
    }

    @Override
    public String getName() {
      return name;
    }
  }

}
