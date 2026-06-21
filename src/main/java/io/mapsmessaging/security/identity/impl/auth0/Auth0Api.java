/*
 * Copyright [ 2020 - 2024 ] Matthew Buckton
 *  Copyright [ 2024 - 2026 ] MapsMessaging B.V.
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

import com.auth0.client.mgmt.ManagementApi;
import com.auth0.client.mgmt.core.ManagementApiException;
import com.auth0.client.mgmt.core.SyncPagingIterable;
import com.auth0.client.mgmt.types.ListUsersRequestParameters;
import com.auth0.client.mgmt.types.Role;
import com.auth0.client.mgmt.types.RoleUser;
import com.auth0.client.mgmt.types.UserResponseSchema;
import io.mapsmessaging.security.identity.impl.external.WebRequestCaching;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

public class Auth0Api {
  private static final String LIST_USER_REQUEST = "ListUsersRequest";
  private static final String LIST_GROUP_REQUEST = "ListGroupRequest";
  private static final String USER_IN_GROUP_REQUEST = "GetUserInGroup";

  private final WebRequestCaching caching;
  private final ManagementApi managementApi;

  public Auth0Api(ManagementApi managementApi, long cacheAge) {
    caching = new WebRequestCaching(cacheAge);
    this.managementApi = managementApi;
  }

  public boolean isUserCacheValid() {
    return caching.get(LIST_USER_REQUEST) != null;
  }

  public boolean isGroupCacheValid() {
    return caching.get(LIST_GROUP_REQUEST) != null;
  }

  @SuppressWarnings("unchecked")
  public List<String> getUserInGroup(String groupName) throws ManagementApiException {
    String cacheKey = USER_IN_GROUP_REQUEST + "(" + groupName + ")";
    List<String> users = (List<String>) caching.get(cacheKey);
    if (users != null) {
      return users;
    }

    List<String> usersInGroup = new ArrayList<>();
    SyncPagingIterable<RoleUser> roleUsers = managementApi.roles().users().list(groupName);

    for (RoleUser user : roleUsers) {
      if(user.getEmail().isPresent()){
        usersInGroup.add(user.getEmail().get());
      }
    }

    caching.put(cacheKey, usersInGroup);
    return usersInGroup;
  }

  @SuppressWarnings("unchecked")
  public List<Role> getGroupList() throws ManagementApiException {
    List<Role> responseList = (List<Role>) caching.get(LIST_GROUP_REQUEST);
    if (responseList != null) {
      return responseList;
    }

    responseList = new ArrayList<>();
    SyncPagingIterable<Role> roles = managementApi.roles().list();

    for (Role role : roles) {
      responseList.add(role);
    }

    caching.put(LIST_GROUP_REQUEST, responseList);
    return responseList;
  }

  @SuppressWarnings("unchecked")
  public List<UserResponseSchema> getUserList() throws ManagementApiException {
    List<UserResponseSchema> responseList = (List<UserResponseSchema>) caching.get(LIST_USER_REQUEST);
    if (responseList != null) {
      return responseList;
    }

    responseList = new ArrayList<>();
    SyncPagingIterable<UserResponseSchema> users =
        managementApi.users().list(
            ListUsersRequestParameters.builder()
                .perPage(100)
                .build());

    for (UserResponseSchema user : users) {
      responseList.add(user);
    }

    responseList =
        responseList.stream()
            .filter(user -> !user.getBlocked().orElse(false))
            .collect(Collectors.toList());

    caching.put(LIST_USER_REQUEST, responseList);
    return responseList;
  }
}