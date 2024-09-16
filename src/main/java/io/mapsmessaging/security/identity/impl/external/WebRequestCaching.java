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

package io.mapsmessaging.security.identity.impl.external;

import java.util.Map;
import java.util.WeakHashMap;

public class WebRequestCaching {

  private final long cacheAge;
  private final Map<String, WebResult> requests = new WeakHashMap<>();

  public WebRequestCaching(long cacheAge) {
    this.cacheAge = cacheAge;
  }

  public Object get(String request) {
    WebResult result = requests.get(request);
    if (result != null) {
      if (result.getExpiryTime() >= System.currentTimeMillis()) {
        return result.getResult();
      }
      requests.remove(request);
    }
    return null;
  }

  public void put(String listUsersRequest, Object response) {
    long age = System.currentTimeMillis() + cacheAge;
    requests.put(listUsersRequest, new WebResult(response, age));
  }
}
