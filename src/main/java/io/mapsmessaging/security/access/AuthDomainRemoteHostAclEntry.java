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

public class AuthDomainRemoteHostAclEntry extends SimpleAclEntry {

  private final String authDomain;
  private final String remoteHost;

  public AuthDomainRemoteHostAclEntry(String username, String authDomain, String remoteHost, long access) {
    super(username, access);
    this.authDomain = authDomain;
    this.remoteHost = remoteHost;
  }

  @Override
  public boolean matches(String authDomain, String username, String remoteHost) {
    return super.matches(authDomain, username, remoteHost) &&
        this.remoteHost.equals(remoteHost) &&
        this.authDomain.equals(authDomain);
  }


}
