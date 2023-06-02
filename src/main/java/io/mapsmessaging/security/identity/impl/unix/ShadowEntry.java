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

package io.mapsmessaging.security.identity.impl.unix;

import com.sun.security.auth.UserPrincipal;
import io.mapsmessaging.security.identity.GroupEntry;
import io.mapsmessaging.security.identity.IdentityEntry;
import io.mapsmessaging.security.identity.parsers.PasswordParserFactory;
import io.mapsmessaging.security.identity.principals.FullNamePrincipal;
import io.mapsmessaging.security.identity.principals.HomeDirectoryPrinicipal;
import java.security.Principal;
import java.util.HashSet;
import java.util.Set;
import lombok.Getter;
import lombok.Setter;

public class ShadowEntry extends IdentityEntry {

  @Getter
  @Setter
  private PasswordEntry passwordEntry;

  public ShadowEntry(String line) {
    int usernamePos = line.indexOf(":");
    username = line.substring(0, usernamePos);
    line = line.substring(usernamePos + 1);
    int endOfPassword = line.indexOf(":");
    password = line.substring(0, endOfPassword);
    passwordParser = PasswordParserFactory.getInstance().parse(password);
  }

  @Override
  protected Set<Principal> getPrincipals(){
    Set<Principal> principals = super.getPrincipals();
    if(passwordEntry != null){
      principals.add(new FullNamePrincipal(passwordEntry.getDescription()));
      principals.add(new HomeDirectoryPrinicipal(passwordEntry.getHomeDirectory()));
    }
    return principals;
  }


}
