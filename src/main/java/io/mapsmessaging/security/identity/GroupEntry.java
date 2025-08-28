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

package io.mapsmessaging.security.identity;

import java.util.Set;
import java.util.TreeSet;
import lombok.Getter;

/**
 * Represents a group in the context of authentication.
 *
 * <p>A group is a collection of users who share common access rights or permissions within an
 * authentication system. It provides a way to organize and manage users based on their roles,
 * privileges, or other criteria.
 *
 * <p>The {@code GroupEntry} class encapsulates the properties and behavior of a group, including
 * the group name and the set of users belonging to the group.
 *
 * <p>The {@code GroupEntry} class implements the {@link Comparable} interface, allowing groups to
 * be compared and sorted based on their names.
 *
 * <p>Usage:
 *
 * <pre>{@code
 * // Create a new group
 * Set<String> userSet = new TreeSet();
 * // Add users to the group
 * userSet.add(string1);
 * userSet.add(string2);
 *
 * GroupEntry group = new GroupEntry("Group1", userSet);
 *
 *
 * // Check if a authentication Id is in the group
 * boolean isInGroup = group.isInGroup(uuid);
 *
 * // Get the group name
 * String groupName = group.getName();
 * }</pre>
 *
 * @see Comparable
 */
public class GroupEntry {

  protected final Set<String> userSet;

  @Getter
  protected String name;

  public GroupEntry() {
    name = "";
    userSet = new TreeSet<>();
  }

  public GroupEntry(String name, Set<String> userSet) {
    this.name = name;
    this.userSet = userSet;
  }

  public void addUser(String user) {
    userSet.add(user);
  }

  public boolean isInGroup(String check) {
    return userSet.contains(check);
  }

  public void removeUser(String username) {
    userSet.remove(username);
  }

  public Set<String> getUsers() {
    return Set.copyOf(userSet);
  }

  public int getUserCount() {
    return userSet.size();
  }

  public String toString() {
    StringBuilder sb = new StringBuilder(name).append(":");
    boolean isFirst = true;
    for (String user : userSet) {
      if (!isFirst) sb.append(" ");
      isFirst = false;
      sb.append(user);
    }

    return sb.toString();
  }
}
