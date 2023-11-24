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

package io.mapsmessaging.security.identity.impl.apache;

import io.mapsmessaging.security.identity.IdentityEntry;
import io.mapsmessaging.security.identity.IdentityLookup;
import io.mapsmessaging.security.identity.NoSuchUserFoundException;
import io.mapsmessaging.security.identity.impl.base.FileBaseGroups;
import io.mapsmessaging.security.identity.impl.base.FileBaseIdentities;
import java.io.File;
import java.util.Map;

public class ApacheBasicAuth implements IdentityLookup {

  private final FileBaseIdentities passwdFileManager;
  private final FileBaseGroups groupFileManager;

  public ApacheBasicAuth(){
    passwdFileManager = null;
    groupFileManager = null;
  }

  public ApacheBasicAuth(String passwordFile, String groupFile){
    passwdFileManager = new HtPasswdFileManager(passwordFile);
    groupFileManager = new HtGroupFileManager(groupFile);
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
    if (passwdFileManager == null) {
      return null;
    }
    IdentityEntry identityEntry = passwdFileManager.findEntry(username);
    if(identityEntry != null){
      groupFileManager.loadGroups(identityEntry);
    }
    return identityEntry;
  }

  @Override
  public IdentityLookup create(Map<String, ?> config) {
    if (config.containsKey("passwordFile")) {
      String filePath = config.get("passwordFile").toString();
      String groupFile = "";
      if(config.containsKey("groupFile")){
        groupFile = config.get("groupFile").toString();
      }
      return new ApacheBasicAuth(filePath, groupFile);
    }
    if(config.containsKey("configDirectory")){
      String directory = config.get("configDirectory").toString();
      File file = new File(directory);
      if (!file.exists()) {
        file.mkdirs();
      }
      if(file.isDirectory()){
        return new ApacheBasicAuth(file.getAbsolutePath()+File.separator+".htpassword", file.getAbsolutePath()+File.separator+".htgroups");
      }
    }
    return null;
  }

}
