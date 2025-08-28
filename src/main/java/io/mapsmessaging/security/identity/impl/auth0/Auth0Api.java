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

package io.mapsmessaging.security.identity.impl.auth0;

import com.auth0.client.mgmt.ManagementAPI;
import com.auth0.client.mgmt.filter.RolesFilter;
import com.auth0.client.mgmt.filter.UserFilter;
import com.auth0.exception.Auth0Exception;
import com.auth0.json.mgmt.roles.Role;
import com.auth0.json.mgmt.roles.RolesPage;
import com.auth0.json.mgmt.users.User;
import com.auth0.json.mgmt.users.UsersPage;
import com.auth0.net.Request;
import io.mapsmessaging.security.identity.impl.external.WebRequestCaching;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

public class Auth0Api {
  private static final String LIST_USER_REQUEST = "ListUsersRequest";
  private static final String LIST_GROUP_REQUEST = "ListGroupRequest";
  private static final String USER_IN_GROUP_REQUEST = "GetUserInGroup";

  private final WebRequestCaching caching;
  private final ManagementAPI mgmt;

  public Auth0Api(ManagementAPI mgmt, long cacheAge) {
    caching = new WebRequestCaching(cacheAge);
    this.mgmt = mgmt;
  }

  public boolean isUserCacheValid() {
    return caching.get(LIST_USER_REQUEST) != null;
  }

  public boolean isGroupCacheValid() {
    return caching.get(LIST_GROUP_REQUEST) != null;
  }

  public List<String> getUserInGroup(String groupname) throws Auth0Exception {
    List<String> users = (List<String>) caching.get(USER_IN_GROUP_REQUEST+"(" + groupname + ")");
    if (users != null) {
      return users;
    }
    List<String> users1 = new ArrayList<>();
    mgmt.roles()
        .listUsers(groupname, null)
        .execute()
        .getBody()
        .getItems()
        .forEach(user -> users1.add(user.getEmail()));
    caching.put(USER_IN_GROUP_REQUEST+"(" + groupname + ")", users1);
    return users1;
  }

  public List<Role> getGroupList() throws Auth0Exception {
    List<Role> responseList = (List<Role>) caching.get(LIST_GROUP_REQUEST);
    if (responseList != null) {
      return responseList;
    }
    int start = 0;
    int limit = 100;
    mgmt.roles().list(new RolesFilter().withPage(start, limit));
    RolesPage rolesPage =
        mgmt.roles().list(new RolesFilter().withPage(start, limit)).execute().getBody();
    List<Role> roleList = rolesPage.getItems();
    start = start + roleList.size();
    responseList = new ArrayList<>(roleList);
    if (rolesPage.getTotal() != null && rolesPage.getTotal() > start) {
      while (rolesPage.getTotal() > start) {
        rolesPage = mgmt.roles().list(new RolesFilter().withPage(start, limit)).execute().getBody();
        roleList = rolesPage.getItems();
        start = start + roleList.size();
        responseList.addAll(roleList);
      }
    }
    caching.put(LIST_GROUP_REQUEST, responseList);
    return responseList;
  }

  public List<User> getUserList() throws Auth0Exception {
    List<User> responseList = (List<User>) caching.get(LIST_USER_REQUEST);
    if (responseList != null) {
      return responseList;
    }
    int start = 0;
    int limit = 100;
    Request<UsersPage> request = mgmt.users().list(null);
    UsersPage usersPage = request.execute().getBody();
    List<User> userList = usersPage.getItems();
    start += userList.size();
    responseList = new ArrayList<>(userList);
    if (usersPage.getTotal() != null && usersPage.getTotal() > start) {
      while (usersPage.getTotal() > start) {
        request = mgmt.users().list(new UserFilter().withPage(start, limit));
        usersPage = request.execute().getBody();
        start = start + usersPage.getLength();
        userList = usersPage.getItems();
        responseList.addAll(userList);
      }
    }
    responseList =
        responseList.stream()
            .filter(user -> (user.isBlocked() == null || !user.isBlocked()))
            .collect(Collectors.toList());
    caching.put(LIST_USER_REQUEST, responseList);
    return responseList;
  }
}
