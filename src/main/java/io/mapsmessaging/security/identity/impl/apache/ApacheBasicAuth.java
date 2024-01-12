/*
 * Copyright [ 2020 - 2024 ] [Matthew Buckton]
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

package io.mapsmessaging.security.identity.impl.apache;

import io.mapsmessaging.security.identity.*;
import io.mapsmessaging.security.identity.impl.base.FileBaseGroups;
import io.mapsmessaging.security.identity.impl.base.FileBaseIdentities;
import io.mapsmessaging.security.identity.parsers.PasswordParser;
import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;

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

  protected ApacheBasicAuth(HtPasswdFileManager passwordFile, HtGroupFileManager groupFile) {
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
  public char[] getPasswordHash(String username) throws NoSuchUserFoundException {
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
    return groupFileManager.findGroup(groupName);
  }

  @Override
  public List<GroupEntry> getGroups() {
    return groupFileManager.getGroups();
  }

  @Override
  public void updateGroup(GroupEntry groupEntry) throws IOException {
    groupFileManager.deleteEntry(groupEntry.getName());
    groupFileManager.addEntry(groupEntry.toString());
  }

  @Override
  public List<IdentityEntry> getEntries() {
    return passwdFileManager.getEntries();
  }

  @Override
  public IdentityLookup create(Map<String, ?> config) {
    if (config.containsKey("passwordFile")) {
      String filePath = config.get("passwordFile").toString();
      String groupFile = "";
      if (config.containsKey("groupFile")) {
        groupFile = config.get("groupFile").toString();
      }
      return new ApacheBasicAuth(filePath, groupFile);
    }
    if (config.containsKey("configDirectory")) {
      String directory = config.get("configDirectory").toString();
      File file = new File(directory);
      if (file.isDirectory()) {
        return new ApacheBasicAuth(file.getAbsolutePath() + File.separator + ".htpassword", file.getAbsolutePath() + File.separator + ".htgroups");
      }
    }
    return null;
  }

  @Override
  public boolean createUser(String username, String password, PasswordParser passwordParser) throws IOException {
    String salt = PasswordGenerator.generateSalt(16);
    byte[] hash =
        passwordParser.transformPassword(
            password.getBytes(StandardCharsets.UTF_8), salt.getBytes(StandardCharsets.UTF_8), 12);
    if (passwdFileManager != null) {
      passwdFileManager.addEntry(username, new String(hash));
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
}
