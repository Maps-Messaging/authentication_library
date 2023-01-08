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

package io.mapsmessaging.security.jaas;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;

public class Auth0Helper {

  public static Properties getProperties() throws IOException {
    Properties prop = new Properties();
    try (InputStream input = Auth0Helper.class.getClassLoader().getResourceAsStream("Auth0.properties")) {
      if (input != null) {
        prop.load(input);
        return prop;
      }
    }
    try (InputStream input = new FileInputStream("Auth0.properties")) {
      prop.load(input);
      return prop;
    } catch (FileNotFoundException ex) {
      // ignore this since we can fall through
    }
    return System.getProperties();
  }

}