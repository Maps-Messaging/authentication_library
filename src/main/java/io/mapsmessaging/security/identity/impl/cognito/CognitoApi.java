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

package io.mapsmessaging.security.identity.impl.cognito;

import io.mapsmessaging.security.identity.impl.external.WebRequestCaching;
import software.amazon.awssdk.services.cognitoidentityprovider.CognitoIdentityProviderClient;
import software.amazon.awssdk.services.cognitoidentityprovider.model.*;

public class CognitoApi {
  private static final String LIST_USER_REQUEST = "ListUsersRequest";
  private static final String LIST_GROUP_REQUEST = "ListGroupRequest";
  private static final String USER_IN_GROUP_REQUEST = "GetUserInGroup";

  private final CognitoIdentityProviderClient cognitoClient;
  private final WebRequestCaching caching;
  private final String userPoolId;

  public CognitoApi(CognitoIdentityProviderClient cognitoClient, String userPoolId, long cacheAge) {
    this.cognitoClient = cognitoClient;
    caching = new WebRequestCaching(cacheAge);
    this.userPoolId = userPoolId;
  }

  public ListUsersResponse getUserList() {
    ListUsersResponse response = (ListUsersResponse) caching.get(LIST_USER_REQUEST);
    if (response == null) {
      ListUsersRequest usersRequest = ListUsersRequest.builder().userPoolId(userPoolId).build();
      response = cognitoClient.listUsers(usersRequest);
      caching.put(LIST_USER_REQUEST, response);
    }
    return response;
  }

  public ListUsersInGroupResponse getUsersInGroup(String name) {
    ListUsersInGroupResponse listUsersInGroupResponse =
        (ListUsersInGroupResponse) caching.get(USER_IN_GROUP_REQUEST+"(" + name + ")");
    if (listUsersInGroupResponse == null) {
      ListUsersInGroupRequest listUsersInGroupRequest =
          ListUsersInGroupRequest.builder().userPoolId(userPoolId).groupName(name).build();
      listUsersInGroupResponse = cognitoClient.listUsersInGroup(listUsersInGroupRequest);
      caching.put(USER_IN_GROUP_REQUEST+"(" + name + ")", listUsersInGroupResponse);
    }
    return listUsersInGroupResponse;
  }

  public ListGroupsResponse getGroupList() {
    ListGroupsResponse response = (ListGroupsResponse) caching.get(LIST_GROUP_REQUEST);
    if (response == null) {
      ListGroupsRequest listGroupsRequest =
          ListGroupsRequest.builder().userPoolId(userPoolId).build();
      response = cognitoClient.listGroups(listGroupsRequest);
      caching.put(LIST_GROUP_REQUEST, response);
    }
    return response;
  }

  public boolean isUserCacheValid() {
    return caching.get(LIST_USER_REQUEST) != null;
  }

  public boolean isGroupCacheValid() {
    return caching.get(LIST_GROUP_REQUEST) != null;
  }
}
