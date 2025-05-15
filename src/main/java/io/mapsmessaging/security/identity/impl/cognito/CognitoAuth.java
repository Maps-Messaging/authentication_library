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

package io.mapsmessaging.security.identity.impl.cognito;

import io.mapsmessaging.configuration.ConfigurationProperties;
import io.mapsmessaging.security.identity.GroupEntry;
import io.mapsmessaging.security.identity.IdentityEntry;
import io.mapsmessaging.security.identity.IdentityLookup;
import io.mapsmessaging.security.identity.NoSuchUserFoundException;
import io.mapsmessaging.security.identity.impl.external.CachingIdentityLookup;
import io.mapsmessaging.security.passwords.PasswordBuffer;
import io.mapsmessaging.security.passwords.PasswordHandler;
import java.util.ArrayList;
import java.util.List;
import lombok.Getter;
import software.amazon.awssdk.auth.credentials.AwsCredentials;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.cognitoidentityprovider.CognitoIdentityProviderClient;
import software.amazon.awssdk.services.cognitoidentityprovider.model.*;

@Getter
public class CognitoAuth extends CachingIdentityLookup<CognitoIdentityEntry> {

  private final String userPoolId;
  private final String appClientId;
  private final String appClientSecret;
  private final String regionName;
  private long cacheTime = 30000;

  private final CognitoIdentityProviderClient cognitoClient;
  private final CognitoApi cognitoApi;

  public CognitoAuth() {
    cognitoClient = null;
    cognitoApi = null;
    userPoolId = "";
    appClientId = "";
    regionName = "";
    appClientSecret = "";
  }

  public CognitoAuth(ConfigurationProperties config) {
    userPoolId = config.getProperty("userPoolId");
    appClientId = config.getProperty("appClientId");
    appClientSecret = config.getProperty("appClientSecret");

    regionName = config.getProperty("region");
    String accesskeyId = config.getProperty("accessKeyId");
    String secretAccessKey = config.getProperty("secretAccessKey");

    String cacheTimeString = config.getProperty("cacheTime");
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
    cognitoApi = new CognitoApi(cognitoClient, userPoolId, cacheTime);
  }

  @Override
  public IdentityLookup create(ConfigurationProperties config) {
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
  public PasswordBuffer getPasswordHash(String username) throws NoSuchUserFoundException {
    return new PasswordBuffer(new char[0]);
  }

  @Override
  public List<IdentityEntry> getEntries() {
    loadUsers();
    return new ArrayList<>(identityEntries);
  }

  protected void loadUsers() {
    if (cognitoApi.isUserCacheValid()) {
      return;
    }
    identityEntryMap.clear();
    identityEntries.clear();
    ListUsersResponse response = cognitoApi.getUserList();
    List<UserType> userList = response.users();
    for (UserType user : userList) {
      if (Boolean.TRUE.equals(user.enabled())) {
        List<AttributeType> list = user.attributes();
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
    if (cognitoApi.isGroupCacheValid()) {
      return;
    }
    groupEntryMap.clear();
    ListGroupsResponse listGroupsResponse = cognitoApi.getGroupList();
    for (GroupType groupType : listGroupsResponse.groups()) {
      CognitoGroupEntry groupEntry = new CognitoGroupEntry(groupType.groupName());
      ListUsersInGroupResponse listUsersInGroupResponse =
          cognitoApi.getUsersInGroup(groupType.groupName());
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
  public boolean createGroup(String groupName) {
    CreateGroupResponse response = cognitoClient.createGroup(CreateGroupRequest.builder().groupName(groupName).userPoolId(userPoolId).build());
    if (response.sdkHttpResponse().isSuccessful()) {
      groupEntryMap.put(groupName, new CognitoGroupEntry(groupName));
      return true;
    }
    return false;
  }

  @Override
  public boolean deleteGroup(String groupName) {
    DeleteGroupResponse response = cognitoClient.deleteGroup(DeleteGroupRequest.builder().groupName(groupName).userPoolId(userPoolId).build());
    if (response.sdkHttpResponse().isSuccessful()) {
      groupEntryMap.remove(groupName);
      return true;
    }
    return false;
  }

  @Override
  public boolean createUser(String username, char[] passwordHash, PasswordHandler passwordHasher) {
    List<AttributeType> userAttributes = new ArrayList<>();
    if (username.contains("@")) {
      userAttributes.add(AttributeType.builder().name("email_verified").value("true").build());
      userAttributes.add(AttributeType.builder().name("email").value(username).build());
    }
    AdminCreateUserRequest request =
        AdminCreateUserRequest.builder()
            .userPoolId(userPoolId)
            .userAttributes(userAttributes)
            .username(username)
            .build();

    AdminCreateUserResponse response = cognitoClient.adminCreateUser(request);
    if (response.sdkHttpResponse().isSuccessful()) {
      CognitoIdentityEntry entry = new CognitoIdentityEntry(this, username, "");
      identityEntryMap.put(username, entry);
      identityEntries.add(entry);
      return true;
    }
    return false;
  }

  @Override
  public boolean deleteUser(String username) {
    AdminDeleteUserRequest deleteUserRequest = AdminDeleteUserRequest.builder().username(username).userPoolId(userPoolId).build();
    AdminDeleteUserResponse response = cognitoClient.adminDeleteUser(deleteUserRequest);
    if (response.sdkHttpResponse().isSuccessful()) {
      identityEntryMap.remove(username);
      identityEntries.removeIf(identityEntry -> identityEntry.getUsername().equals(username));
      return true;
    }
    return false;
  }

  @Override
  protected void loadGroups(CognitoIdentityEntry identityEntry) {
    loadGroups();
  }

  @Override
  protected IdentityEntry createIdentityEntry(String username) {
    return new CognitoIdentityEntry(this, username, null);
  }
}