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

package io.mapsmessaging.security.identity.impl.ldap;

import io.mapsmessaging.security.identity.IdentityEntry;
import io.mapsmessaging.security.identity.parsers.PasswordParserFactory;
import java.security.Principal;
import java.util.Enumeration;
import java.util.Set;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;

public class LdapEntry extends IdentityEntry {

  private final Attributes attrs;

  public LdapEntry(String username, char[] password, Attributes attrs) {
    super.username = username;
    super.password = new String(password);
    super.passwordParser = PasswordParserFactory.getInstance().parse(new String(password));
    this.attrs = attrs;
  }


  @Override
  protected Set<Principal> getPrincipals(){
    Set<Principal> principals = getPrincipals();
    Enumeration<? extends Attribute> enumeration= attrs.getAll();
    while(enumeration.hasMoreElements()){
      Attribute attribute = enumeration.nextElement();
      if(!attribute.getID().equalsIgnoreCase("cn") &&
          !attribute.getID().toLowerCase().contains("password")){
        principals.add(new LdapPrincipal(attribute.toString()));
      }
    }
    return principals;
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
