/*
 * Copyright [ 2020 - 2024 ] Matthew Buckton
 *  Copyright [ 2024 - 2025 ] MapsMessaging B.V.
 *
 *  Licensed under the Apache License, Version 2.0 with the Commons Clause
 *  (the "License"); you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at:
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *      https://commonsclause.com/
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 *
 */

package io.mapsmessaging.security.identity.impl.base;

import static io.mapsmessaging.security.logging.AuthLogMessages.*;

import io.mapsmessaging.logging.Logger;
import io.mapsmessaging.logging.LoggerFactory;
import io.mapsmessaging.security.identity.IllegalFormatException;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

public abstract class FileLoader {

  private final Logger logger = LoggerFactory.getLogger(FileLoader.class);
  private final String filePath;
  private final File file;
  private long lastModified;

  protected FileLoader(String filepath) {
    filePath = filepath;
    file = new File(filePath);
    lastModified = 0;
  }

  protected abstract void parse(String line) throws IllegalFormatException;

  public void load() {
    logger.log(CHECKING_PASSWORD_STORE, filePath);
    if (file.exists() && lastModified != file.lastModified()) {
      logger.log(PASSWORD_FILE_CHANGE_DETECTED, filePath);
      lastModified = file.lastModified();
      int lineNo = 0;
      try (BufferedReader reader = new BufferedReader(new FileReader(file))) {
        String line = reader.readLine();
        lineNo++;
        while (line != null) {
          parse(line);
          line = reader.readLine();
        }
      } catch (IOException e) {
        logger.log(PASSWORD_FILE_LOAD_EXCEPTION, filePath, lineNo, e);
      }
    }
  }

  protected void add(String line) throws IOException {
    if (!file.exists() && !file.createNewFile()) {
      logger.log(FAILED_TO_CREATE_FILE, file.getAbsolutePath());
      throw new IOException("Unable to create new file " + file.getAbsolutePath());
    }

    try (BufferedWriter bw = new BufferedWriter(new FileWriter(file, true))) {
      bw.write(line);
      bw.newLine(); // Add a newline character after each line
    }
  }

  protected void delete(String name) throws IOException {
    File tempFile = new File(file.getAbsolutePath() + ".tmp");

    try (BufferedReader reader = new BufferedReader(new FileReader(file));
         BufferedWriter writer = new BufferedWriter(new FileWriter(tempFile))) {

      String lineToRemove = name + ":";
      String currentLine;

      while ((currentLine = reader.readLine()) != null) {
        if (!currentLine.startsWith(lineToRemove)) {
          writer.write(currentLine + System.lineSeparator());
        }
      }
    }

    Path path = Paths.get(file.getAbsolutePath());
    try {
      Files.delete(path);
    } catch (IOException e) {
      logger.log(FAILED_TO_DELETE_FILE, path.toAbsolutePath().toString());
      throw new IOException("Could not delete original file: " + e.getMessage(), e);
    }

    if (!tempFile.renameTo(file)) {
      logger.log(FAILED_TO_RENAME_FILE, tempFile.getAbsolutePath(), file.getAbsolutePath());
      throw new IOException("Could not rename temporary file");
    }
  }
}
