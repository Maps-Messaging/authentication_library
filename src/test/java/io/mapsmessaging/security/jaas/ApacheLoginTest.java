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

package io.mapsmessaging.security.jaas;

import java.util.LinkedHashMap;
import java.util.Map;

class ApacheLoginTest extends BaseIdentity {

  Map<String, String> getOptions() {
    Map<String, String> options = new LinkedHashMap<>();
    options.put("identityName", "Apache-Basic-Auth");
    options.put("configDirectory", "./src/test/resources/apache");
    return options;
  }

  @Override
  String getUser() {
    return "test2";
  }

  @Override
  String getPassword() {
    return "This is an md5 password";
  }
}
