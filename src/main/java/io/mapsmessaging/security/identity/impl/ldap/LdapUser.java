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
import io.mapsmessaging.security.identity.principals.FullNamePrincipal;
import io.mapsmessaging.security.identity.principals.HomeDirectoryPrinicipal;
import java.security.Principal;
import java.util.Enumeration;
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
    super.password = new String(password);
    super.passwordParser = PasswordParserFactory.getInstance().parse(new String(password));
    this.attrs = attrs;
    NamingEnumeration<? extends Attribute> namingEnum =  attrs.getAll();
    while(namingEnum.hasMoreElements()){
      Attribute attribute = namingEnum.nextElement();
      try {
        if(attribute.getID().equalsIgnoreCase("homedirectory")){
          homeDirectory = (String) attribute.get();
        }
        else if(attribute.getID().equalsIgnoreCase("gecos")){
          description = (String) attribute.get();
        }

      } catch (NamingException e) {
        throw new RuntimeException(e);
      }
    }
  }


  @Override
  protected Set<Principal> getPrincipals(){
    Set<Principal> principals = getPrincipals();
    if(homeDirectory != null){
      principals.add(new HomeDirectoryPrinicipal(homeDirectory));
    }
    if(description != null){
      principals.add(new FullNamePrincipal(description));
    }
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
