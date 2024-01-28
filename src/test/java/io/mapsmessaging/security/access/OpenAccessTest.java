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

package io.mapsmessaging.security.access;

import io.mapsmessaging.security.access.open.OpenAccessControlList;
import java.io.IOException;
import java.security.GeneralSecurityException;
import javax.security.auth.Subject;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

public class OpenAccessTest {

  @Test
  void ensureOpenWorks(){
    AccessControlList openAccessControlList = AccessControlFactory.getInstance().get("Open", null,null);
    Assertions.assertEquals("Open", openAccessControlList.getName());
    Assertions.assertEquals(OpenAccessControlList.class, openAccessControlList.create(null, null).getClass());
  }


  @Test
  public void testAccessControlListCreation() throws IOException, GeneralSecurityException {
    OpenAccessControlList identityAccessManager = new OpenAccessControlList();
    Subject subject = new Subject();
    for (int x = 0; x < 100; x++) {
      Assertions.assertTrue(identityAccessManager.canAccess(subject, 0));
    }
  }

}
