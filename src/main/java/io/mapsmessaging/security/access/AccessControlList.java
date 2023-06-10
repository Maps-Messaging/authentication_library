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

package io.mapsmessaging.security.access;

import com.sun.security.auth.UserPrincipal;
import io.mapsmessaging.security.identity.GroupEntry;
import io.mapsmessaging.security.identity.principals.RemoteHostPrincipal;
import java.security.Principal;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;
import javax.security.auth.Subject;


public class AccessControlList {

  private final List<AclEntry> aclEntries;

  public AccessControlList() {
    aclEntries = new ArrayList<>();
  }

  public AccessControlList(List<AclEntry> aclEntries) {
    this.aclEntries = new ArrayList<>(aclEntries);
  }

  public long getSubjectAccess(Subject subject) {
    long mask = 0;
    if (subject != null) {
      String username = getUsername(subject);
      String remoteHost = getRemoteHost(subject);

      for (AclEntry aclEntry : aclEntries) {
        if (aclEntry.matches(username, remoteHost)) {
          mask = mask | aclEntry.getAccessBitset();
        }
      }

      // Scan the groups for access
      for (Principal group : subject.getPrincipals().stream().filter(principal -> principal instanceof GroupEntry).collect(Collectors.toList())) {
        for (AclEntry aclEntry : aclEntries) {
          if (aclEntry.matches(group.getName(), remoteHost)) {
            mask = mask | aclEntry.getAccessBitset();
          }
        }
      }
    }
    return mask;
  }


  public boolean canAccess(Subject subject, long requestedAccess) {
    if (subject == null || requestedAccess == 0) {
      return false;
    }

    String username = getUsername(subject);
    String remoteHost = getRemoteHost(subject);

    // Scan for username / host for access
    for (AclEntry aclEntry : aclEntries) {
      if ((aclEntry.getAccessBitset() & requestedAccess) == requestedAccess && aclEntry.matches(username, remoteHost)) {
        return true;
      }
    }

    // Scan the groups for access
    for(Principal group:subject.getPrincipals().stream().filter(principal -> principal instanceof GroupEntry).collect(Collectors.toList())){
      for (AclEntry aclEntry : aclEntries) {
        if ((aclEntry.getAccessBitset() & requestedAccess) == requestedAccess && aclEntry.matches(group.getName(), remoteHost) ) {
          return true;
        }
      }
    }

    // This means neither user nor group has access
    return false;
  }

  private String getUsername(Subject subject) {
    UserPrincipal userPrincipal = subject.getPrincipals(UserPrincipal.class).stream().findFirst().orElse(null);
    return (userPrincipal != null) ? userPrincipal.getName() : null;
  }

  private String getRemoteHost(Subject subject) {
    RemoteHostPrincipal remoteHostPrincipal = subject.getPrincipals(RemoteHostPrincipal.class).stream().findFirst().orElse(null);
    return (remoteHostPrincipal != null) ? remoteHostPrincipal.getName() : null;
  }

}