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

package io.mapsmessaging.security.identity.impl.apache;

import io.mapsmessaging.configuration.ConfigurationProperties;
import io.mapsmessaging.security.identity.*;
import io.mapsmessaging.security.identity.impl.base.FileBaseGroups;
import io.mapsmessaging.security.identity.impl.base.FileBaseIdentities;
import io.mapsmessaging.security.passwords.PasswordBuffer;
import io.mapsmessaging.security.passwords.PasswordHandler;
import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.List;

public class ApacheBasicAuth implements IdentityLookup {

  protected final FileBaseIdentities passwdFileManager;
  protected final FileBaseGroups groupFileManager;

  public ApacheBasicAuth() {
    passwdFileManager = null;
    groupFileManager = null;
  }

  public ApacheBasicAuth(String passwordFile, String groupFile) {
    passwdFileManager = new HtPasswdFileManager(passwordFile);
    groupFileManager = new HtGroupFileManager(groupFile);
  }

  protected ApacheBasicAuth(FileBaseIdentities passwordFile, HtGroupFileManager groupFile) {
    passwdFileManager = passwordFile;
    groupFileManager = groupFile;
  }

  @Override
  public String getName() {
    return "Apache-Basic-Auth";
  }

  @Override
  public String getDomain() {
    return "apache";
  }

  @Override
  public PasswordBuffer getPasswordHash(String username) throws IOException, GeneralSecurityException {
    if (passwdFileManager == null) {
      throw new NoSuchUserFoundException(username);
    }
    return passwdFileManager.getPasswordHash(username);
  }

  @Override
  public IdentityEntry findEntry(String username) {
    if (passwdFileManager == null || groupFileManager == null) {
      return null;
    }
    IdentityEntry identityEntry = passwdFileManager.findEntry(username);
    if (identityEntry != null) {
      groupFileManager.loadGroups(identityEntry);
    }
    return identityEntry;
  }

  @Override
  public GroupEntry findGroup(String groupName) {
    if (groupFileManager != null) {
      return groupFileManager.findGroup(groupName);
    }
    return null;
  }

  @Override
  public List<GroupEntry> getGroups() {
    if (groupFileManager != null) {
      return groupFileManager.getGroups();
    }
    return new ArrayList<>();
  }

  @Override
  public void updateGroup(GroupEntry groupEntry) throws IOException {
    if (groupFileManager != null) {
      groupFileManager.deleteEntry(groupEntry.getName());
      groupFileManager.addEntry(groupEntry.toString());
    }
  }

  @Override
  public List<IdentityEntry> getEntries() {
    if (passwdFileManager != null) {
      return passwdFileManager.getEntries();
    }
    return new ArrayList<>();
  }

  @Override
  public IdentityLookup create(ConfigurationProperties config) {
    if (config.containsKey("passwordFile")) {
      String filePath = config.getProperty("passwordFile");
      String groupFile = "";
      if (config.containsKey("groupFile")) {
        groupFile = config.getProperty("groupFile");
      }
      return new ApacheBasicAuth(filePath, groupFile);
    }
    if (config.containsKey("configDirectory")) {
      String directory = config.getProperty("configDirectory");
      File file = new File(directory);
      if (file.isDirectory()) {
        return new ApacheBasicAuth(file.getAbsolutePath() + File.separator + ".htpassword", file.getAbsolutePath() + File.separator + ".htgroups");
      }
    }
    return null;
  }

  @Override
  public boolean createUser(String username, char[] password, PasswordHandler handler)
      throws IOException, GeneralSecurityException {
    String salt = PasswordGenerator.generateSalt(16);
    char[] hash =
        handler.transformPassword(password, salt.getBytes(StandardCharsets.UTF_8), 12);
    if (passwdFileManager != null) {
      passwdFileManager.addEntry(username, hash);
      return true;
    }
    return false;
  }

  @Override
  public boolean deleteUser(String username) throws IOException {
    if (passwdFileManager != null) {
      passwdFileManager.deleteEntry(username);
      return true;
    }
    return false;
  }

  @Override
  public boolean createGroup(String groupName) throws IOException {
    if (groupFileManager != null) {
      groupFileManager.addEntry(groupName);
      return true;
    }
    return false;
  }

  @Override
  public boolean deleteGroup(String groupName) throws IOException {
    if (groupFileManager != null) {
      groupFileManager.deleteEntry(groupName);
      return true;
    }
    return false;
  }

  @Override
  public boolean canManage(){
    return true;
  }
}
