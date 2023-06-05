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
  private final String searchFilter;

  private final String groupSearchBase;
  private final String groupSearchFilter;

  private final Map<String, LdapUser> userMap;
  private final Map<String, GroupEntry> groupList;

  private DirContext directoryContext;
  private SearchControls searchControls;

  public LdapUserManager(Map<String, ?> config) throws NamingException {
    Hashtable<String, String> map = new Hashtable<>();
    for (Entry<String, ?> entry : config.entrySet()) {
      map.put(entry.getKey(), entry.getValue().toString());
    }
    passwordName = config.get("passwordKeyName").toString();

    userMap = new LinkedHashMap<>();
    groupList = new LinkedHashMap<>();
    searchBase = config.get("searchBase").toString();
    searchFilter = config.get("searchFilter").toString();
    groupSearchBase = config.get("groupSearchBase").toString();
    groupSearchFilter = config.get("groupSearchFilter").toString();

    load(map);
  }

  public char[] getPasswordHash(String username) throws NoSuchUserFoundException {
    LdapUser entry = userMap.get(username);
    if (entry != null) {
      return entry.getPasswordParser().getFullPasswordHash();
    }
    throw new NoSuchUserFoundException("Password entry for " + username + " not found");
  }

  private void load( Hashtable<String, String> map) throws NamingException {
    searchControls = new SearchControls();
    String[] returnedAtts = {"sn", "cn", "givenName", "gecos", "homeDirectory", passwordName};
    searchControls.setReturningAttributes(returnedAtts);
    searchControls.setSearchScope(SearchControls.SUBTREE_SCOPE);

    directoryContext = new InitialDirContext(map);
    getGroup();
    loadUsers();
    directoryContext.close();
  }

  private void loadUsers(){
    try {
      NamingEnumeration<SearchResult> results = directoryContext.search(searchBase, searchFilter, searchControls);
      // Iterate over the search results and print the user information
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
            for(GroupEntry ldapGroup:groupList.values()){
              if(ldapGroup.isInGroup(ldapUser.getUsername())){
                ldapUser.addGroup(ldapGroup);
              }
            }

            userMap.put(ldapUser.getUsername(), ldapUser);
          }
        }
      }
    } catch (NamingException e) {
      e.printStackTrace();
    }
  }

  private void getGroup() throws NamingException {
    String[] attributes = {"cn","memberuid"};

    SearchControls groupSearchControls = new SearchControls();
    groupSearchControls.setReturningAttributes(attributes);
    groupSearchControls.setSearchScope(SearchControls.SUBTREE_SCOPE);

    // Perform LDAP search
    NamingEnumeration<SearchResult> searchResults = directoryContext.search(groupSearchBase, groupSearchFilter, groupSearchControls);
    while(searchResults.hasMoreElements()){
      SearchResult result = searchResults.nextElement();
      Attributes attrs = result.getAttributes();
      if(attrs.size() > 0){
        Attribute groupName = attrs.get("cn");
        Attribute members = attrs.get("memberUid");
        if(groupName != null && members != null){
          Set<String> memberList = new TreeSet<>();
          NamingEnumeration<?> naming = members.getAll();
          while(naming.hasMoreElements()){
            memberList.add((String) naming.nextElement());
          }
          GroupEntry group = new GroupEntry((String)groupName.get(), memberList);
          groupList.put(group.getName(), group);
        }
      }
    }
  }

  public IdentityEntry findEntry(String username) {
    return userMap.get(username);
  }

}