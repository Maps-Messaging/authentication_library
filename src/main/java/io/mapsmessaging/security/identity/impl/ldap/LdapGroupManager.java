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

import io.mapsmessaging.security.identity.NoSuchUserFoundException;
import java.util.Enumeration;
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

public class LdapGroupManager {

  private final DirContext directoryContext;
  private final String searchBase;
  private final String searchFilter;
  private final SearchControls searchControls;

  public LdapGroupManager(Map<String, ?> config) throws NamingException {
    Hashtable<String, String> map = new Hashtable<>();
    for (Entry<String, ?> entry : config.entrySet()) {
      map.put(entry.getKey(), entry.getValue().toString());
    }
    directoryContext = new InitialDirContext(map);
    searchBase = config.get("searchBase").toString();
    searchFilter = config.get("searchFilter").toString();
    searchControls = new SearchControls();
    searchControls.setSearchScope(SearchControls.SUBTREE_SCOPE);
    load();
  }

  private void load() {
    try {
      NamingEnumeration<SearchResult> results = directoryContext.search(searchBase, searchFilter, searchControls);
      // Iterate over the search results and print the user information
      while (results.hasMore()) {
        SearchResult result = results.next();
        Attributes attrs = result.getAttributes();
        NamingEnumeration<? extends Attribute> enumeration = attrs.getAll();
        while(enumeration.hasMoreElements()){
          System.err.println(enumeration.nextElement().toString());
        }
      }
    } catch (NamingException e) {
      e.printStackTrace();
    }
  }

}
