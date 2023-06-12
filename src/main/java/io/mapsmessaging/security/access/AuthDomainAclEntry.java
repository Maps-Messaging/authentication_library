/*
 * Copyright [ 2020 - 2023 ] [Matthew Buckton]
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package io.mapsmessaging.security.access;

public class AuthDomainAclEntry extends SimpleAclEntry {

  private final String authDomain;

  public AuthDomainAclEntry(String username, String authDomain, long permissions) {
    super(username, permissions);
    this.authDomain = authDomain;
  }

  @Override
  public boolean matches(String authDomain, String username, String remoteHost) {
    return super.matches(authDomain, username, remoteHost) &&
        this.authDomain.equals(authDomain);
  }
}