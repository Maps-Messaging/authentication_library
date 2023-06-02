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
import io.mapsmessaging.security.identity.NoSuchUserFoundException;
import java.util.Hashtable;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Map.Entry;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;

public class LdapUserManager {

  private final DirContext directoryContext;
  private final String searchBase;
  private final String searchFilter;
  private final String passwordName;
  private final SearchControls searchControls;
  private final Map<String, LdapEntry> userMap;

  public LdapUserManager() {
    directoryContext = null;
    searchControls = null;
    searchBase = "";
    searchFilter = "";
    passwordName = "";
    userMap = new LinkedHashMap<>();
  }

  public LdapUserManager(Map<String, ?> config) throws NamingException {
    Hashtable<String, String> map = new Hashtable<>();
    for (Entry<String, ?> entry : config.entrySet()) {
      map.put(entry.getKey(), entry.getValue().toString());
    }
    userMap = new LinkedHashMap<>();
    directoryContext = new InitialDirContext(map);
    searchBase = config.get("searchBase").toString();
    searchFilter = config.get("searchFilter").toString();
    passwordName = config.get("passwordKeyName").toString();
    searchControls = new SearchControls();
    searchControls.setSearchScope(SearchControls.SUBTREE_SCOPE);
    load();
  }

  public char[] getPasswordHash(String username) throws NoSuchUserFoundException {
    LdapEntry entry = userMap.get(username);
    if (entry != null) {
      return entry.getPasswordParser().getFullPasswordHash();
    }
    throw new NoSuchUserFoundException("Password entry for " + username + " not found");
  }

  private void load() {
    try {
      NamingEnumeration<SearchResult> results = directoryContext.search(searchBase, searchFilter, searchControls);
      // Iterate over the search results and print the user information
      while (results.hasMore()) {
        SearchResult result = results.next();
        Attributes attrs = result.getAttributes();
        Attribute user = attrs.get("cn");
        String userString = user.get().toString();
        Attribute password = attrs.get(passwordName);
        if (password != null) {
          Object v = password.get();
          if (v instanceof byte[]) {
            String s = new String((byte[]) v);
            if (s.toLowerCase().startsWith("{crypt}")) {
              s = s.substring("{crypt}".length());
            }
            userMap.put(userString, new LdapEntry(userString, s.toCharArray(), attrs));
          }
        }
      }
    } catch (NamingException e) {
      e.printStackTrace();
    }
  }


  public IdentityEntry findEntry(String username) {
    return userMap.get(username);
  }

}