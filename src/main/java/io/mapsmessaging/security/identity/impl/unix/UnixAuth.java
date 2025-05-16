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

package io.mapsmessaging.security.identity.impl.unix;

import io.mapsmessaging.configuration.ConfigurationProperties;
import io.mapsmessaging.security.identity.GroupEntry;
import io.mapsmessaging.security.identity.IdentityEntry;
import io.mapsmessaging.security.identity.IdentityLookup;
import io.mapsmessaging.security.identity.impl.base.FileBaseIdentities;
import io.mapsmessaging.security.passwords.PasswordBuffer;
import java.io.File;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.List;

public class UnixAuth implements IdentityLookup {

  private FileBaseIdentities passwordFileIdentities;
  private GroupFileManager groupFileManager;
  private PasswordFileManager userDetailsManager;

  public UnixAuth() {
  }

  public UnixAuth(String shadowPath, String passwordPath, String groupPath) {
    passwordFileIdentities = new ShadowFileManager(shadowPath);
    if (groupPath != null) {
      groupFileManager = new GroupFileManager(groupPath);
    }
    if (passwordPath != null) {
      userDetailsManager = new PasswordFileManager(passwordPath);
    }
    for(IdentityEntry identityEntry:passwordFileIdentities.getEntries()){
      groupFileManager.loadGroups(identityEntry);
    }
  }

  @Override
  public String getName() {
    return "unix";
  }

  @Override
  public String getDomain() {
    return getName();
  }

  @Override
  public PasswordBuffer getPasswordHash(String username) throws IOException, GeneralSecurityException {
    return passwordFileIdentities.getPasswordHash(username);
  }

  @Override
  public IdentityEntry findEntry(String username) {
    IdentityEntry identityEntry = passwordFileIdentities.findEntry(username);
    if (identityEntry != null && userDetailsManager != null && groupFileManager != null) {
      PasswordEntry passwordEntry = userDetailsManager.findUser(username);
      if (passwordEntry != null) {
        int groupId = passwordEntry.getGroupId();
        ((ShadowEntry) identityEntry).setPasswordEntry(passwordEntry);
        GroupEntry groupEntry = groupFileManager.findGroup(groupId);
        identityEntry.clearGroups();
        if (groupEntry != null) {
          identityEntry.addGroup(groupEntry);
        }
      }
    }
    return identityEntry;
  }

  @Override
  public GroupEntry findGroup(String groupName) {
    return groupFileManager.findGroup(groupName);
  }

  @Override
  public List<GroupEntry> getGroups() {
    return groupFileManager.getGroups();
  }

  @Override
  public List<IdentityEntry> getEntries() {
    return passwordFileIdentities.getEntries();
  }

  @Override
  public IdentityLookup create(ConfigurationProperties config) {
    if (config.containsKey("passwordFile")) {
      String filePath = config.getProperty("passwordFile");
      String groupFile = config.getProperty("groupFile");
      String passwordFile = config.getProperty("passwd");

      return new UnixAuth(filePath, passwordFile, groupFile);
    }
    if (config.containsKey("configDirectory")) {
      String directory = config.getProperty("configDirectory");
      File file = new File(directory);
      if (file.isDirectory()) {
        return new UnixAuth(file.getAbsolutePath() + File.separator + "shadow", file.getAbsolutePath() + File.separator + "passwd", file.getAbsolutePath() + File.separator + "group");
      }
    }
    return null;
  }
}
