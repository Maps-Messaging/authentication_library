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

package io.mapsmessaging.security.identity;

import io.mapsmessaging.security.identity.parsers.PasswordParser;

import java.io.IOException;
import java.util.List;
import java.util.Map;

public interface IdentityLookup {

  String getName();

  String getDomain();

  char[] getPasswordHash(String username) throws NoSuchUserFoundException;

  boolean createUser(String username, String passwordHash, PasswordParser passwordParser) throws IOException;

  IdentityEntry findEntry(String username);

  List<IdentityEntry> getEntries();

  IdentityLookup create(Map<String, ?> config);

  void deleteUser(String username) throws IOException;
}
