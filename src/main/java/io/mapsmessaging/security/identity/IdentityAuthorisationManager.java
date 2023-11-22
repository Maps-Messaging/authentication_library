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

package io.mapsmessaging.security.identity;

import io.mapsmessaging.security.SubjectHelper;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import javax.security.auth.Subject;

public class IdentityAuthorisationManager {

  private final Map<String, UUID> lookupMap;

  public IdentityAuthorisationManager() {
    lookupMap = new ConcurrentHashMap<>();
  }

  public UUID getAuthId(String username, String authDomain, String remoteHost) {
    return lookupMap.get(setKey(username, authDomain, remoteHost));
  }

  public void setAuthId(String username, String authDomain, String remoteHost, UUID authId) {
    lookupMap.put(setKey(username, authDomain, remoteHost), authId);
  }

  private String setKey(String username, String authDomain, String remoteHost) {
    if (authDomain == null) authDomain = "any";
    if (remoteHost == null) remoteHost = "*";
    return username + ":" + authDomain + "@" + remoteHost;
  }

  public void setAuthId(Subject subject) {
    String username = SubjectHelper.getUsername(subject);
    String remoteHost = SubjectHelper.getRemoteHost(subject);
    String authDomain = SubjectHelper.getAuthDomain(subject);
    UUID authId = SubjectHelper.getUniqueId(subject);
    setAuthId(username, authDomain, remoteHost, authId);
  }
}
