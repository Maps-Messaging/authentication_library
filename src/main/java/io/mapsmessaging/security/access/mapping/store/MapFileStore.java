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

package io.mapsmessaging.security.access.mapping.store;

import static io.mapsmessaging.security.logging.AuthLogMessages.FAILED_TO_CREATE_FILE;
import static io.mapsmessaging.security.logging.AuthLogMessages.PASSWORD_FILE_LOAD_EXCEPTION;

import io.mapsmessaging.logging.Logger;
import io.mapsmessaging.logging.LoggerFactory;
import io.mapsmessaging.security.access.mapping.IdMap;
import io.mapsmessaging.security.access.mapping.MapParser;
import java.io.*;
import java.util.ArrayList;
import java.util.List;

public class MapFileStore<T extends IdMap> implements MapStore<T> {

  private final Logger logger = LoggerFactory.getLogger(MapFileStore.class);
  private final String fileName;

  public MapFileStore(String fileName) {
    this.fileName = fileName;
  }

  public List<T> load(MapParser<T> parser) {
    List<T> entries = new ArrayList<>();
    int lineNo = 0;
    try (BufferedReader br = new BufferedReader(new FileReader(fileName))) {
      String line;
      while ((line = br.readLine()) != null) {
        lineNo++;
        T entry = parser.parse(line);
        if (entry != null) {
          entries.add(entry);
        }
      }
    } catch (IOException e) {
      logger.log(PASSWORD_FILE_LOAD_EXCEPTION, fileName, lineNo, e);
    }
    return entries;
  }

  public void save(List<T> entries, MapParser<T> parser) {
    try (BufferedWriter bw = new BufferedWriter(new FileWriter(fileName))) {
      List<String> linesToWrite = parser.writeToList(entries);
      for (String line : linesToWrite) {
        bw.write(line);
        bw.newLine(); // Add a newline character after each line
      }
    } catch (IOException e) {
      logger.log(FAILED_TO_CREATE_FILE, fileName, e);
    }
  }
}
