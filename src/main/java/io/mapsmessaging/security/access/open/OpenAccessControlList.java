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

package io.mapsmessaging.security.access.open;

import io.mapsmessaging.security.access.AccessControlList;
import io.mapsmessaging.security.access.AccessControlMapping;
import java.util.List;
import javax.security.auth.Subject;

public class OpenAccessControlList implements AccessControlList {

  @Override
  public String getName() {
    return "Open";
  }

  @Override
  public AccessControlList create(AccessControlMapping accessControlMapping, List<String> config) {
    return new OpenAccessControlList();
  }

  @Override
  public long getSubjectAccess(Subject subject) {
    return 0xffffffffffffffffL;
  }

  @Override
  public boolean canAccess(Subject subject, long requestedAccess) {
    return true;
  }
}
