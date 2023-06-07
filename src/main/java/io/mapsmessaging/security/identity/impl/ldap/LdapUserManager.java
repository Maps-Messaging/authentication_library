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

import io.mapsmessaging.security.identity.GroupEntry;
import io.mapsmessaging.security.identity.IdentityEntry;
import io.mapsmessaging.security.identity.NoSuchUserFoundException;
import java.util.Hashtable;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;
import java.util.TreeSet;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;

public class LdapUserManager {

  private final String passwordName;

  private final String searchBase;
  private final String groupSearchBase;

  private final Map<String, LdapUser> userMap;

  private final Hashtable<String, String> map;

  public LdapUserManager(Map<String, ?> config) throws NamingException {
    map = new Hashtable<>();
    for (Entry<String, ?> entry : config.entrySet()) {
      map.put(entry.getKey(), entry.getValue().toString());
    }
    passwordName = config.get("passwordKeyName").toString();

    userMap = new LinkedHashMap<>();
    searchBase = config.get("searchBase").toString();
    groupSearchBase = config.get("groupSearchBase").toString();
  }

  public IdentityEntry findEntry(String username) {
    LdapUser entry = userMap.get(username);
    if(entry == null){
      entry = findUser(username);
    }
    return entry;
  }

  public char[] getPasswordHash(String username) throws NoSuchUserFoundException {
    IdentityEntry entry = findEntry(username);
    if (entry != null) {
      return entry.getPasswordParser().getFullPasswordHash();
    }
    throw new NoSuchUserFoundException("Password entry for " + username + " not found");
  }

  private LdapUser findUser(String username){
    SearchControls searchControls = new SearchControls();
    String[] returnedAtts = {"cn", "givenName", "gecos", "homeDirectory", "gidNumber", passwordName};
    searchControls.setReturningAttributes(returnedAtts);
    searchControls.setSearchScope(SearchControls.SUBTREE_SCOPE);
    String searchFilter = "(uid=" + username + ")";
    DirContext directoryContext = null;
    try {
      directoryContext = new InitialDirContext(map);
      NamingEnumeration<SearchResult> results = directoryContext.search(searchBase, searchFilter, searchControls);
      while (results.hasMore()) {
        SearchResult result = results.next();
        Attributes attrs = result.getAttributes();

        Attribute user = attrs.get("cn");
        String userString = (String)user.get();
        Attribute password = attrs.get(passwordName);
        if (password != null) {
          Object v = password.get();
          if (v instanceof byte[]) {
            String s = new String((byte[]) v);
            if (s.toLowerCase().startsWith("{crypt}")) {
              s = s.substring("{crypt}".length());
            }
            LdapUser ldapUser = new LdapUser(userString, s.toCharArray(), attrs);
            loadGroups(ldapUser, directoryContext, username);
            userMap.put(ldapUser.getUsername(), ldapUser);
            return ldapUser;
          }
        }
      }
    } catch (NamingException e) {
      throw new RuntimeException(e);
    }
    finally{
      if(directoryContext != null){
        try {
          directoryContext.close();
        } catch (NamingException e) {
          throw new RuntimeException(e);
        }
      }
    }
    return null;
  }

  private void loadGroups(LdapUser ldapUser, DirContext directoryContext, String userId) throws NamingException {
    String[] attributes = {"cn"};
    SearchControls groupSearchControls = new SearchControls();
    groupSearchControls.setReturningAttributes(attributes);
    groupSearchControls.setSearchScope(SearchControls.SUBTREE_SCOPE);

    // Perform LDAP search
    NamingEnumeration<SearchResult> searchResults = directoryContext.search(groupSearchBase, "(memberUid=" + userId + ")", groupSearchControls);
    while(searchResults.hasMoreElements()){
      SearchResult result = searchResults.nextElement();
      Attributes attrs = result.getAttributes();
      if(attrs.size() > 0){
        Attribute groupName = attrs.get("cn");
        if(groupName != null ){
          Set<String> memberList = new TreeSet<>();
          memberList.add(userId);
          GroupEntry group = new GroupEntry((String)groupName.get(), memberList);
          ldapUser.addGroup(group);
        }
      }
    }

  }


}