/*
 * Copyright [ 2020 - 2024 ] Matthew Buckton
 *  Copyright [ 2024 - 2025 ] MapsMessaging B.V.
 *
 *  Licensed under the Apache License, Version 2.0 with the Commons Clause
 *  (the "License"); you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at:
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *      https://commonsclause.com/
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 *
 */

package io.mapsmessaging.security.authorisation.impl.openfga;

import io.mapsmessaging.security.authorisation.Grantee;
import io.mapsmessaging.security.authorisation.GranteeType;
import io.mapsmessaging.security.authorisation.Permission;
import io.mapsmessaging.security.authorisation.ProtectedResource;

import java.util.Locale;
import java.util.UUID;

public class ReadHelper {

  private final OpenFGAAuthorizationProvider openFGAAuthorizationProvider;

  public ReadHelper(OpenFGAAuthorizationProvider authorizationProvider) {
    this.openFGAAuthorizationProvider = authorizationProvider;
  }

  public  Grantee parseUserToGrantee(String user) {
    if (user == null || user.isEmpty()) {
      return null;
    }

    // Strip relation suffix for group grants: "group:<id>#member"
    String core = user;
    int hashIndex = user.indexOf('#');
    if (hashIndex > 0) {
      core = user.substring(0, hashIndex);
    }

    int colonIndex = core.indexOf(':');
    if (colonIndex <= 0 || colonIndex >= core.length() - 1) {
      return null;
    }

    String type = core.substring(0, colonIndex);
    String idPart = core.substring(colonIndex + 1);

    UUID id;
    try {
      id = UUID.fromString(idPart);
    } catch (IllegalArgumentException illegalArgumentException) {
      return null;
    }

    if (type.equals(openFGAAuthorizationProvider.getUserType())) {
      return new Grantee(GranteeType.USER, id );
    }

    if (type.equals(openFGAAuthorizationProvider.getGroupType())) {
      return new Grantee(GranteeType.GROUP, id);
    }

    return null;
  }

  public Permission toPermission(String relation) {
    if (relation == null || relation.isEmpty()) {
      return null;
    }
    try {
      return openFGAAuthorizationProvider.getPermissions().get(relation.toLowerCase(Locale.ROOT));
    } catch (IllegalArgumentException illegalArgumentException) {
      return null;
    }
  }

  public ProtectedResource fromObject(String object) {
    if (object == null || object.isEmpty()) {
      return null;
    }

    int colonIndex = object.indexOf(':');
    if (colonIndex <= 0 || colonIndex >= object.length() - 1) {
      return null;
    }

    String resourceType = object.substring(0, colonIndex);
    String rest = object.substring(colonIndex + 1);

    String tenant = "";
    String resourceId = rest;

    int sepIndex = rest.indexOf(openFGAAuthorizationProvider.getTenantSeparator());
    if (sepIndex >= 0) {
      tenant = rest.substring(0, sepIndex);
      resourceId = rest.substring(sepIndex + openFGAAuthorizationProvider.getTenantSeparator().length());
    }

    // Adjust to whatever constructor/factory you actually have
    return new ProtectedResource(resourceType, resourceId, tenant);
  }

}
