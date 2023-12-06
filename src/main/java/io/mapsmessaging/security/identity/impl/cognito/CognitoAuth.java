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

import io.mapsmessaging.security.identity.GroupEntry;
import io.mapsmessaging.security.identity.IdentityEntry;
import io.mapsmessaging.security.identity.IdentityLookup;
import io.mapsmessaging.security.identity.NoSuchUserFoundException;
import io.mapsmessaging.security.identity.parsers.PasswordParser;
import java.io.IOException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import lombok.Getter;
import software.amazon.awssdk.auth.credentials.AwsCredentials;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.cognitoidentityprovider.CognitoIdentityProviderClient;
import software.amazon.awssdk.services.cognitoidentityprovider.model.*;

@Getter
public class CognitoAuth implements IdentityLookup {

  private final String userPoolId;
  private final String appClientId;
  private final String appClientSecret;
  private long lastUpdated = 0;
  private long cacheTime = 30000;

  private final Map<String, GroupEntry> groupEntryMap = new LinkedHashMap<>();
  private final Map<String, CognitoIdentityEntry> identityEntryMap = new LinkedHashMap<>();
  private final List<CognitoIdentityEntry> identityEntries = new ArrayList<>();

  private final CognitoIdentityProviderClient cognitoClient;

  public CognitoAuth() {
    cognitoClient = null;
    userPoolId = "";
    appClientId = "";
    appClientSecret = "";
  }

  public CognitoAuth(Map<String, ?> config) {
    userPoolId = (String) config.get("userPoolId");
    appClientId = (String) config.get("appClientId");
    appClientSecret = (String) config.get("appClientSecret");

    String regionName = (String) config.get("region");
    String accesskeyId = (String) config.get("accessKeyId");
    String secretAccessKey = (String) config.get("secretAccessKey");

    String cacheTimeString = (String) config.get("cacheTime");
    if(cacheTimeString != null && !cacheTimeString.trim().isEmpty()){
      cacheTime = Long.parseLong(cacheTimeString.trim());
    }

    Region region = Region.of(regionName);

    AwsCredentials credentials = new CognitoCredentials(accesskeyId, secretAccessKey);
    cognitoClient = CognitoIdentityProviderClient.
        builder().
        credentialsProvider(() -> credentials).
        region(region).
        build();

  }

  @Override
  public IdentityLookup create(Map<String, ?> config) {
    return new CognitoAuth(config);
  }

  @Override
  public String getName() {
    return "cognito";
  }

  @Override
  public String getDomain() {
    return getName();
  }

  @Override
  public char[] getPasswordHash(String username) throws NoSuchUserFoundException {
    return new char[0];
  }

  @Override
  public IdentityEntry findEntry(String username) {
    loadUsers();
    return identityEntryMap.get(username);
  }

  @Override
  public List<IdentityEntry> getEntries() {
    loadUsers();
    return new ArrayList<>(identityEntries);
  }

  protected void loadUsers() {
    long time = System.currentTimeMillis();
    if (time < lastUpdated) {
      return;
    }
    lastUpdated = time + cacheTime;
    ListUsersRequest usersRequest = ListUsersRequest.builder().userPoolId(userPoolId).build();
    ListUsersResponse response = cognitoClient.listUsers(usersRequest);
    List<UserType> userList = response.users();
    for (UserType user : userList) {
      if (user.enabled()) {
        List<software.amazon.awssdk.services.cognitoidentityprovider.model.AttributeType> list = user.attributes();
        AttributeType email = list.stream().filter(attributeType -> attributeType.name().equals("email")).findFirst().orElse(null);
        AttributeType uuid = list.stream().filter(attributeType -> attributeType.name().equals("sub")).findFirst().orElse(null);
        AttributeType profile = list.stream().filter(attributeType -> attributeType.name().equals("profile")).findFirst().orElse(null);
        if (uuid != null) {
          CognitoIdentityEntry entry = new CognitoIdentityEntry(this, user.username(), uuid.value());
          if (profile != null) entry.setProfile(profile.value());
          identityEntryMap.put(user.username(), entry);
          identityEntries.add(entry);
          if (email != null) {
            entry.setEmail(email.value());
            identityEntryMap.put(email.value(), entry);
          }
        }
      }
    }
    loadGroups();
  }

  private void loadGroups() {
    ListGroupsRequest listGroupsRequest = ListGroupsRequest.builder().userPoolId(userPoolId).build();
    ListGroupsResponse listGroupsResponse = cognitoClient.listGroups(listGroupsRequest);
    for (GroupType groupType : listGroupsResponse.groups()) {
      CognitoGroupEntry groupEntry = new CognitoGroupEntry(groupType.groupName());
      ListUsersInGroupRequest listUsersInGroupRequest = ListUsersInGroupRequest.builder().userPoolId(userPoolId).groupName(groupType.groupName()).build();
      ListUsersInGroupResponse listUsersInGroupResponse = cognitoClient.listUsersInGroup(listUsersInGroupRequest);
      for (UserType userType : listUsersInGroupResponse.users()) {
        String username = userType.username();
        CognitoIdentityEntry identityEntry = identityEntryMap.get(username);
        if (identityEntry != null) {
          groupEntry.addUser(userType.username());
          identityEntry.addGroup(groupEntry);
        }
      }
      groupEntryMap.put(groupType.groupName(), groupEntry);
    }
  }

  @Override
  public GroupEntry findGroup(String groupName) {
    return groupEntryMap.get(groupName);
  }

  @Override
  public List<GroupEntry> getGroups() {
    return new ArrayList<>(groupEntryMap.values());
  }


  @Override
  public boolean createGroup(String groupName) throws IOException {
    CreateGroupResponse response = cognitoClient.createGroup(CreateGroupRequest.builder().groupName(groupName).userPoolId(userPoolId).build());
    if (response.sdkHttpResponse().isSuccessful()) {
      reset();
      return true;
    }
    return false;
  }

  @Override
  public boolean deleteGroup(String groupName) throws IOException {
    DeleteGroupResponse response = cognitoClient.deleteGroup(DeleteGroupRequest.builder().groupName(groupName).userPoolId(userPoolId).build());
    if (response.sdkHttpResponse().isSuccessful()) {
      reset();
      return true;
    }
    return false;
  }

  @Override
  public boolean createUser(String username, String passwordHash, PasswordParser passwordParser) throws IOException {
    AdminCreateUserResponse response = cognitoClient.adminCreateUser(AdminCreateUserRequest.builder().userPoolId(userPoolId).username(username).temporaryPassword(passwordHash).build());
    if (response.sdkHttpResponse().isSuccessful()) {
      reset();
      return true;
    }
    return false;
  }

  @Override
  public boolean deleteUser(String username) throws IOException {
    AdminDeleteUserRequest deleteUserRequest = AdminDeleteUserRequest.builder().username(username).userPoolId(userPoolId).build();
    AdminDeleteUserResponse response = cognitoClient.adminDeleteUser(deleteUserRequest);
    if (response.sdkHttpResponse().isSuccessful()) {
      reset();
      return true;
    }
    return false;
  }

  @Override
  public void updateGroup(GroupEntry groupEntry) throws IOException {
    IdentityLookup.super.updateGroup(groupEntry);
  }

  private void reset() {
    groupEntryMap.clear();
    this.identityEntries.clear();
    this.identityEntryMap.clear();
    lastUpdated = 0;
    loadUsers();
  }
}