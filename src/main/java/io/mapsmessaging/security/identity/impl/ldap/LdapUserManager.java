/*
 * Copyright [ 2020 - 2024 ] [Matthew Buckton]
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

import io.mapsmessaging.configuration.ConfigurationProperties;
import io.mapsmessaging.logging.Logger;
import io.mapsmessaging.logging.LoggerFactory;
import io.mapsmessaging.security.identity.GroupEntry;
import io.mapsmessaging.security.identity.IdentityEntry;
import io.mapsmessaging.security.identity.NoSuchUserFoundException;
import io.mapsmessaging.security.logging.AuthLogMessages;
import io.mapsmessaging.security.util.ArrayHelper;
import java.util.*;
import java.util.Map.Entry;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.*;

public class LdapUserManager {

  private static final char[] CRYPT_ARRAY = "{crypt}".toCharArray();

  private final Logger logger = LoggerFactory.getLogger(LdapUserManager.class);
  private final String passwordName;

  private final String searchBase;
  private final String groupSearchBase;

  private final Map<String, LdapUser> userMap;
  private final Map<String, LdapGroup> groupMap;
  private final Map<String, String> map;

  public LdapUserManager(ConfigurationProperties config) {
    map = new LinkedHashMap<>();
    for (Entry<String, ?> entry : config.entrySet()) {
      map.put(entry.getKey(), entry.getValue().toString());
    }
    if(!map.containsKey("java.naming.factory.initial")){
      map.put("java.naming.factory.initial", "com.sun.jndi.ldap.LdapCtxFactory");
    }
    if(!map.containsKey("java.naming.security.authentication")){
      map.put("java.naming.security.authentication", "simple");
    }
    passwordName = config.getProperty("passwordKeyName");

    userMap = new LinkedHashMap<>();
    groupMap = new LinkedHashMap<>();
    searchBase = config.getProperty("searchBase");
    groupSearchBase = config.getProperty("groupSearchBase");
    load();
  }


  private void load(){
    SearchControls searchControls = new SearchControls();
    String[] returnedAtts = {"cn" };
    searchControls.setReturningAttributes(returnedAtts);
    searchControls.setSearchScope(SearchControls.SUBTREE_SCOPE);
    String searchFilter =  "(cn=*)";
    DirContext directoryContext = null;
    List<String> usernames = new ArrayList<>();
    try {
      directoryContext = new InitialDirContext(new Hashtable<>(map));
      loadGroups(null, directoryContext, "*");

      NamingEnumeration<SearchResult> results = directoryContext.search(searchBase, searchFilter, searchControls);
      while(results.hasMore()){
        SearchResult result = results.nextElement();
        Attributes attrs = result.getAttributes();
        Attribute user = attrs.get("cn");
        String userString = (String) user.get();
        usernames.add(userString);
      }
    } catch (NamingException e) {
      logger.log(AuthLogMessages.LDAP_LOAD_FAILURE, e);
    } finally {
      if (directoryContext != null) {
        try {
          directoryContext.close();
        } catch (NamingException e) {
          // we can ignore the close exception here
        }
      }
    }
    for(String username:usernames){
      findUser(username);
    }

  }

  public IdentityEntry findEntry(String username) {
    LdapUser entry = userMap.get(username);
    if (entry == null) {
      entry = findUser(username);
    }
    return entry;
  }

  public char[] getPasswordHash(String username) throws NoSuchUserFoundException {
    IdentityEntry entry = findEntry(username);
    if (entry != null) {
      return entry.getPasswordHasher().getFullPasswordHash();
    }
    throw new NoSuchUserFoundException("Password entry for " + username + " not found");
  }

  private LdapUser findUser(String username) {
    SearchControls searchControls = new SearchControls();
    String[] returnedAtts = {"cn", "givenName", "gecos", "homeDirectory", "gidNumber", passwordName};
    searchControls.setReturningAttributes(returnedAtts);
    searchControls.setSearchScope(SearchControls.SUBTREE_SCOPE);
    String searchFilter = "(uid=" + username + ")";
    DirContext directoryContext = null;
    try {
      directoryContext = new InitialDirContext(new Hashtable<>(map));
      NamingEnumeration<SearchResult> results = directoryContext.search(searchBase, searchFilter, searchControls);
      while (results.hasMore()) {
        SearchResult result = results.next();
        Attributes attrs = result.getAttributes();

        Attribute user = attrs.get("cn");
        String userString = (String) user.get();
        Attribute password = attrs.get(passwordName);
        if (password != null) {
          Object v = password.get();
          if (v instanceof byte[]) {
            char[] passwordArray = checkOrAppend(ArrayHelper.byteArrayToCharArray((byte[])v));
            LdapUser ldapUser = new LdapUser(userString, passwordArray, attrs);
            loadGroups(ldapUser, directoryContext, username);
            userMap.put(ldapUser.getUsername(), ldapUser);
            return ldapUser;
          }
        }
      }
    } catch (NamingException e) {
      logger.log(AuthLogMessages.LDAP_LOAD_FAILURE, e);
    } finally {
      if (directoryContext != null) {
        try {
          directoryContext.close();
        } catch (NamingException e) {
          // we can ignore the close exception here
        }
      }
    }
    return null;
  }

  private char[] checkOrAppend(char[] password){
    if (password.length > CRYPT_ARRAY.length && ArrayHelper.startsWithIgnoreCase(password, CRYPT_ARRAY)) {
      return ArrayHelper.substring(password, CRYPT_ARRAY.length);
    }
    return password;
  }

  private void loadGroups(LdapUser ldapUser, DirContext directoryContext, String userId) throws NamingException {
    String[] attributes = {"cn"};
    SearchControls groupSearchControls = new SearchControls();
    groupSearchControls.setReturningAttributes(attributes);
    groupSearchControls.setSearchScope(SearchControls.SUBTREE_SCOPE);

    // Perform LDAP search
    NamingEnumeration<SearchResult> searchResults = directoryContext.search(groupSearchBase, "(memberUid=" + userId + ")", groupSearchControls);
    while (searchResults.hasMoreElements()) {
      SearchResult result = searchResults.nextElement();
      Attributes attrs = result.getAttributes();
      if (attrs.size() > 0) {
        processGroup(ldapUser, attrs.get("cn"));
      }
    }
  }

  private void processGroup(LdapUser ldapUser, Attribute groupName){
    try{
      if (groupName != null) {
        String name = groupName.get().toString();
        LdapGroup groupEntry = groupMap.get(name);
        if(groupEntry == null){
          groupEntry = new LdapGroup(name);
          groupMap.put(groupEntry.getName(), groupEntry);
        }
        if (ldapUser != null) {
          if (!groupEntry.isInGroup(ldapUser.getUsername())) {
            groupEntry.addUser(ldapUser.getUsername());
          }
          if (!ldapUser.isInGroup(name)) {
            ldapUser.addGroup(groupEntry);
          }
        }
      }
    }
    catch(NamingException namingException){
      logger.log(AuthLogMessages.LDAP_LOAD_FAILURE, namingException);
    }
  }

  public List<IdentityEntry> getUsers(){
    return new ArrayList<>(userMap.values());
  }

  public GroupEntry findGroup(String groupName) {
    return groupMap.get(groupName);
  }
}