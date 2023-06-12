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

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;


/**
 * Manager class for creating an Access Control List (ACL) based on a list of ACL entries. ACL entry strings follow the format "identifier = access" where: - The identifier
 * represents a username or group name with an optional `[authDomain:]username[remoteHost]` specifier. The `[authDomain:]` prefix represents an optional authentication domain. The
 * `username` component represents the username. The `[remoteHost]` suffix represents an optional remote host specification enclosed in square brackets. - The access control string
 * specifies the allowed actions using keywords determined by the provided AccessControlMapping implementation. Multiple access control keywords can be separated by the `|` (pipe)
 * character.
 *
 * Example ACL entry string: "ldap:username[remotehost] = Read|Write"
 *
 * The ACL entries are processed to create an Access Control List that can be used for authorization checks based on the provided AccessControlMapping implementation.
 *
 * {@code @See} AccessControlMapping
 */

public class AccessControlListParser {

  private final Pattern IDENTIFIER_PATTERN = Pattern.compile("^(?:([^:\\[]+):)?([^\\[\\]]+)(?:\\[([^\\[\\]]+)\\])?$");

  public AccessControlListParser() {

  }

  /**
   * Creates an Access Control List (ACL) based on the provided list of ACL entries.
   *
   * @param aclEntries the list of ACL entries in the format "identifier = access"
   * @return the created AccessControlList object
   */
  public List<AclEntry> createList(AccessControlMapping accessControlMapping, List<String> aclEntries) {
    List<AclEntry> aclEntryList = new ArrayList<>();

    for (String aclEntry : aclEntries) {
      AclEntry entry = parseAclEntry(accessControlMapping, aclEntry);
      if (entry != null) {
        aclEntryList.add(entry);
      }
    }
    return aclEntryList;
  }

  private AclEntry parseAclEntry(AccessControlMapping accessControlMapping, String aclEntry) {
    String[] parts = aclEntry.split("=");
    if (parts.length == 2) {
      String identifier = parts[0].trim();
      long accessBitset = parseAccessBitset(accessControlMapping, parts[1].trim());
      return createAclEntry(identifier, accessBitset);
    }
    return null;
  }

  public AclEntry createAclEntry(String identifier, long access) {
    Matcher matcher = IDENTIFIER_PATTERN.matcher(identifier);

    if (matcher.matches()) {
      String authDomain = matcher.group(1);
      String username = matcher.group(2);
      String remoteHost = matcher.group(3);

      if (authDomain != null && remoteHost != null) {
        return new AuthDomainRemoteHostAclEntry(username, authDomain, remoteHost, access);
      } else if (authDomain != null) {
        return new AuthDomainAclEntry(username, authDomain, access);
      } else if (remoteHost != null) {
        return new RemoteHostAclEntry(username, remoteHost, access);
      } else {
        return new SimpleAclEntry(username, access);
      }
    }

    throw new IllegalArgumentException("Invalid identifier format: " + identifier);
  }

  private long parseAccessBitset(AccessControlMapping accessControlMapping, String accessControl) {
    long accessBitset = 0;
    String[] accessControls = accessControl.split("\\|");
    for (String access : accessControls) {
      access = access.trim().toLowerCase();
      Long accessValue = accessControlMapping.getAccessValue(access);
      if (accessValue != null) {
        accessBitset |= accessValue;
      }
    }
    return accessBitset;
  }

}