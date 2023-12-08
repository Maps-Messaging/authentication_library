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

package io.mapsmessaging.security.identity.impl.cognito;

import io.mapsmessaging.security.identity.impl.external.WebRequestCaching;
import software.amazon.awssdk.services.cognitoidentityprovider.CognitoIdentityProviderClient;
import software.amazon.awssdk.services.cognitoidentityprovider.model.ListGroupsRequest;
import software.amazon.awssdk.services.cognitoidentityprovider.model.ListGroupsResponse;
import software.amazon.awssdk.services.cognitoidentityprovider.model.ListUsersRequest;
import software.amazon.awssdk.services.cognitoidentityprovider.model.ListUsersResponse;

public class CognitoApi {

  private final CognitoIdentityProviderClient cognitoClient;
  private final WebRequestCaching caching;
  private final String userPoolId;

  public CognitoApi(CognitoIdentityProviderClient cognitoClient, String userPoolId, long cacheAge) {
    this.cognitoClient = cognitoClient;
    caching = new WebRequestCaching(cacheAge);
    this.userPoolId = userPoolId;
  }

  public ListUsersResponse getUserList() {
    ListUsersResponse response = (ListUsersResponse) caching.get("ListUsersRequest");
    if (response == null) {
      ListUsersRequest usersRequest = ListUsersRequest.builder().userPoolId(userPoolId).build();
      response = cognitoClient.listUsers(usersRequest);
      caching.put("ListUsersRequest", response);
    }
    return response;
  }

  public ListGroupsResponse getGroupList() {
    ListGroupsResponse response = (ListGroupsResponse) caching.get("ListGroupsRequest");
    if (response == null) {
      ListGroupsRequest listGroupsRequest =
          ListGroupsRequest.builder().userPoolId(userPoolId).build();
      response = cognitoClient.listGroups(listGroupsRequest);
      caching.put("ListGroupsRequest", response);
    }
    return response;
  }
}
