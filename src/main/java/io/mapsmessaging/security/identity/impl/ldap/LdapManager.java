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

package io.mapsmessaging.security.identity.impl.ldap;

import io.mapsmessaging.security.identity.IdentityEntry;
import io.mapsmessaging.security.identity.IdentityLookup;
import io.mapsmessaging.security.identity.NoSuchUserFoundException;
import java.util.Hashtable;
import java.util.Map;
import java.util.Map.Entry;
import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;

public class LdapManager implements IdentityLookup {

  private final DirContext directoryContext;
  private final String searchBase;
  private final String searchFilter;
  private final String passwordName;
  private final SearchControls searchControls;

  public LdapManager() {
    directoryContext = null;
    searchControls = null;
    searchBase = "";
    searchFilter = "";
    passwordName = "";
  }

  public LdapManager(Map<String, ?> config) throws NamingException {
    Hashtable<String, String> map = new Hashtable<>();
    for (Entry<String, ?> entry : config.entrySet()) {
      map.put(entry.getKey(), entry.getValue().toString());
    }
    directoryContext = new InitialDirContext(map);
    ;
    searchBase = config.get("searchBase").toString();
    searchFilter = config.get("searchFilter").toString();
    passwordName = config.get("passwordKeyName").toString();
    searchControls = new SearchControls();
    searchControls.setSearchScope(SearchControls.SUBTREE_SCOPE);
  }

  @Override
  public String getName() {
    return "ldapPasswordManager";
  }

  @Override
  public char[] getPasswordHash(String username) throws NoSuchUserFoundException {
    try {
      NamingEnumeration<SearchResult> results = directoryContext.search(searchBase, searchFilter, searchControls);
      // Iterate over the search results and print the user information
      while (results.hasMore()) {
        SearchResult result = results.next();
        Attributes attrs = result.getAttributes();
        Attribute attribute = attrs.get(passwordName);
        if (attribute != null) {
          Object v = attribute.get();
          if (v instanceof byte[]) {
            String s = new String((byte[]) v);
            return s.toCharArray();
          }
        }
      }
    } catch (NamingException e) {
      NoSuchUserFoundException noSuchUserFoundException = new NoSuchUserFoundException("Error looking up for " + username);
      noSuchUserFoundException.initCause(e);
      throw noSuchUserFoundException;
    }
    throw new NoSuchUserFoundException("No such user found for " + username);
  }

  @Override
  public IdentityEntry findEntry(String username) {
    try {
      char[] pass = getPasswordHash(username);
      return new LdapEntry(username, pass);
    } catch (NoSuchUserFoundException e) {
      // ignore
    }
    return null;
  }

  @Override
  public IdentityLookup create(Map<String, ?> config) {
    if (config.containsKey(Context.PROVIDER_URL)) {
      try {
        return new LdapManager(config);
      } catch (NamingException e) {
        return null;
      }
    }
    return null;
  }
}