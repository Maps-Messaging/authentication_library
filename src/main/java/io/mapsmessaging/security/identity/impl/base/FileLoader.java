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

package io.mapsmessaging.security.identity.impl.base;

import static io.mapsmessaging.security.logging.AuthLogMessages.CHECKING_PASSWORD_STORE;
import static io.mapsmessaging.security.logging.AuthLogMessages.PASSWORD_FILE_CHANGE_DETECTED;
import static io.mapsmessaging.security.logging.AuthLogMessages.PASSWORD_FILE_LOAD_EXCEPTION;

import io.mapsmessaging.logging.Logger;
import io.mapsmessaging.logging.LoggerFactory;
import io.mapsmessaging.security.identity.IllegalFormatException;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;

public abstract class FileLoader {

  private final Logger logger = LoggerFactory.getLogger(FileLoader.class);
  private final String filePath;
  private long lastModified;

  protected FileLoader(String filepath) {
    filePath = filepath;
    lastModified = 0;
  }

  protected abstract void parse(String line) throws IllegalFormatException;

  public void load() {
    logger.log(CHECKING_PASSWORD_STORE, filePath);
    File file = new File(filePath);
    if (file.exists() && lastModified != file.lastModified()) {
      logger.log(PASSWORD_FILE_CHANGE_DETECTED, filePath);
      lastModified = file.lastModified();
      try (BufferedReader reader = new BufferedReader(new FileReader(file))) {
        String line = reader.readLine();
        while (line != null) {
          parse(line);
          line = reader.readLine();
        }
      } catch (IOException e) {
        logger.log(PASSWORD_FILE_LOAD_EXCEPTION, filePath, e);
      }
    }
  }
}
