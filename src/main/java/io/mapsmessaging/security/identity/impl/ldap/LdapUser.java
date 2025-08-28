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

package io.mapsmessaging.security.identity.impl.ldap;

import io.mapsmessaging.security.identity.IdentityEntry;
import io.mapsmessaging.security.identity.principals.FullNamePrincipal;
import io.mapsmessaging.security.identity.principals.HomeDirectoryPrincipal;
import io.mapsmessaging.security.passwords.PasswordBuffer;
import io.mapsmessaging.security.passwords.PasswordHandlerFactory;
import java.security.Principal;
import java.util.Enumeration;
import java.util.Map;
import java.util.Set;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import lombok.Getter;

public class LdapUser extends IdentityEntry {

  private final Attributes attrs;

  @Getter
  private String homeDirectory;
  @Getter
  private String description;

  public LdapUser(String username, char[] password, Attributes attrs) {
    super.username = username;
    super.password = new PasswordBuffer(password);
    super.passwordHasher = PasswordHandlerFactory.getInstance().parse(password);
    this.attrs = attrs;
    NamingEnumeration<? extends Attribute> namingEnum = attrs.getAll();
    while (namingEnum.hasMoreElements()) {
      Attribute attribute = namingEnum.nextElement();
      try {
        if (attribute.getID().equalsIgnoreCase("homedirectory")) {
          homeDirectory = (String) attribute.get();
        } else if (attribute.getID().equalsIgnoreCase("gecos")) {
          description = (String) attribute.get();
        }
      } catch (NamingException e) {
        // We ignore this since if the attribute exists, but we can not get it then we don't really care
      }
    }
  }


  @Override
  protected Set<Principal> getPrincipals() {
    Set<Principal> principals = super.getPrincipals();
    if (homeDirectory != null) {
      principals.add(new HomeDirectoryPrincipal(homeDirectory));
    }
    if (description != null) {
      principals.add(new FullNamePrincipal(description));
    }
    Enumeration<? extends Attribute> enumeration = attrs.getAll();
    while (enumeration.hasMoreElements()) {
      Attribute attribute = enumeration.nextElement();
      if (!attribute.getID().equalsIgnoreCase("cn") &&
          !attribute.getID().toLowerCase().contains("password")) {
        principals.add(new LdapPrincipal(attribute.toString()));
      }
    }
    return principals;
  }

  @Override
  public void setAttributeMap(Map<String, String> attributeMap) {
    attributeMap.put("homeDirectory", homeDirectory);
    attributeMap.put("description", description);
    NamingEnumeration<? extends Attribute> enumeration = attrs.getAll();
    while (enumeration.hasMoreElements()) {
      Attribute attribute = enumeration.nextElement();
      attributeMap.put(attribute.getID(), attribute.toString());
    }
  }

  static class LdapPrincipal implements Principal {
    private final String name;

    LdapPrincipal(String name) {
      this.name = name;
    }

    @Override
    public String getName() {
      return name;
    }
  }
}
