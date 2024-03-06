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

package io.mapsmessaging.security.identity;

import io.mapsmessaging.configuration.ConfigurationProperties;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.List;
import org.apache.commons.lang3.NotImplementedException;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

public class BaseIdentityTest {

  @Test
  void testAccessExceptions(){
    TestIdentityLookup testIdentityLookup= new TestIdentityLookup();
    Assertions.assertEquals(0, testIdentityLookup.getGroups().size());
    Assertions.assertThrowsExactly(NotImplementedException.class, () -> testIdentityLookup.createGroup("fred"));
    Assertions.assertThrowsExactly(NotImplementedException.class, () -> testIdentityLookup.deleteGroup("fred"));
    Assertions.assertThrowsExactly(NotImplementedException.class, () -> testIdentityLookup.createUser("fred", "", null));
    Assertions.assertThrowsExactly(NotImplementedException.class, () -> testIdentityLookup.deleteUser("fred"));
    Assertions.assertThrowsExactly(NotImplementedException.class, () -> testIdentityLookup.updateGroup(null));

  }

  public class TestIdentityLookup implements IdentityLookup{

    @Override
    public String getName() {
      return null;
    }

    @Override
    public String getDomain() {
      return null;
    }

    @Override
    public char[] getPasswordHash(String username) throws IOException, GeneralSecurityException {
      return new char[0];
    }

    @Override
    public IdentityEntry findEntry(String username) {
      return null;
    }

    @Override
    public List<IdentityEntry> getEntries() {
      return null;
    }

    @Override
    public GroupEntry findGroup(String groupName) {
      return null;
    }

    @Override
    public IdentityLookup create(ConfigurationProperties config) {
      return null;
    }
  }
}
