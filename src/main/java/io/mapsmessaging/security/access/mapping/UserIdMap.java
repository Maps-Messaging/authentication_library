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

package io.mapsmessaging.security.access.mapping;

import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.ToString;

import java.util.UUID;

@Getter
@EqualsAndHashCode(callSuper = true)
@ToString
public class UserIdMap extends IdMap {

  private final String authDomain;
  private final String remoteHost;
  private final String username;

  public UserIdMap(UUID authId, String username, String authDomain, String remoteHost) {
    super(authId);
    this.username = username;
    this.authDomain = authDomain;
    this.remoteHost = remoteHost;
  }

  @Override
  protected String getKey() {
    String tmp = remoteHost != null ? remoteHost : "";
    return authDomain + ":" + username + ": [" + tmp + "]";
  }
}
