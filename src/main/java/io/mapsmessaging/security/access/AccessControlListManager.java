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


/**
 * Manager class for creating an Access Control List (ACL) based on a list of ACL entries.
 * ACL entry strings follow the format "identifier = access" where:
 * - The identifier represents a username or group name with an optional `@remoteHost` specifier.
 *   The `@remoteHost` specifier restricts the identifier to a specific remote host.
 * - The access control string specifies the allowed actions using keywords determined by the provided AccessControlMapping implementation.
 *   Multiple access control keywords can be separated by the `|` (pipe) character.
 *
 * Example ACL entry string: "username@localhost = Read|Write|Create"
 *
 * {@code @See} AccessControlMapping
 */

public class AccessControlListManager {

  private final AccessControlMapping accessControlMapping;

  public AccessControlListManager(AccessControlMapping accessControlMapping) {
    this.accessControlMapping = accessControlMapping;
  }

  /**
   * Creates an Access Control List (ACL) based on the provided list of ACL entries.
   *
   * @param aclEntries the list of ACL entries in the format "identifier = access"
   * @return the created AccessControlList object
   */
  public AccessControlList createAccessControlList(List<String> aclEntries) {
    List<AclEntry> aclEntryList = new ArrayList<>();

    for (String aclEntry : aclEntries) {
      AclEntry entry = parseAclEntry(aclEntry);
      if (entry != null) {
        aclEntryList.add(entry);
      }
    }
    return new AccessControlList(aclEntryList);
  }

  private AclEntry parseAclEntry(String aclEntry) {
    String[] parts = aclEntry.split("=");
    if (parts.length == 2) {
      String identifier = parts[0].trim();
      long accessBitset = parseAccessBitset(parts[1].trim());
      return createAclEntry(identifier, accessBitset);
    }
    return null;
  }

  private long parseAccessBitset(String accessControl) {
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

  private AclEntry createAclEntry(String identifier, long accessBitset) {
    if (identifier.contains("@")) {
      return new RemoteHostAclEntry(identifier, accessBitset);
    } else {
      return new SimpleAclEntry(identifier, accessBitset);
    }
  }
}