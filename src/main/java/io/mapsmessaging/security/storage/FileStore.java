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

package io.mapsmessaging.security.storage;

import java.io.*;
import java.util.Map;

public class FileStore implements Store {

  public FileStore(){
    // NoOp
  }

  @Override
  public String getName() {
    return "File";
  }

  @Override
  public boolean exists(String name) {
    File file = new File(name);
    return file.exists();
  }

  @Override
  public byte[] load(String name) throws IOException {
    File file = new File(name);
    if(!file.exists()){
      throw new IOException("File does not exist");
    }
    byte[] tmp = new byte[(int)file.length()];
    int pos =0;
    try(FileInputStream fis = new FileInputStream(file)) {
      while (pos < tmp.length) {
        int r = fis.read(tmp, pos, tmp.length - pos);
        if (r < 0) {
          throw new EOFException();
        }
        pos += r;
      }
    }
    return tmp;
  }

  @Override
  public void save(byte[] data, String name) throws IOException {
    try(FileOutputStream fos = new FileOutputStream(name, false)){
      fos.write(data);
    }
  }

  @Override
  public Store create(Map<String, Object> config) {
    return new FileStore();
  }
}
