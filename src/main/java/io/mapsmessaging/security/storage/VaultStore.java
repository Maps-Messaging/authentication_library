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
import com.bettercloud.vault.Vault;
import com.bettercloud.vault.VaultConfig;
import com.bettercloud.vault.VaultException;
import com.bettercloud.vault.response.LogicalResponse;
import java.io.IOException;
import java.util.Base64;
import java.util.Map;

public class VaultStore implements Store {

  private final Vault vault;
  private final String keyName;

  public VaultStore(Vault vault, String keyName) {
    this.vault = vault;
    this.keyName = keyName;
  }

  @Override
  public String getName() {
    return "Vault";
  }

  @Override
  public boolean exists(String name) {
    return false;
  }

  @Override
  public byte[] load(String name) throws IOException {
    try {
      LogicalResponse response = vault.logical().read(name);
      if (response == null || response.getData() == null) {
        throw new IOException("Secret not found");
      }
      String base64Data = response.getData().get(keyName);
      return Base64.getDecoder().decode(base64Data);
    } catch (VaultException e) {
      throw new IOException("Error reading from Vault", e);
    }
  }

  @Override
  public void save(byte[] data, String name) throws IOException {
    try {
      String base64Data = Base64.getEncoder().encodeToString(data);
      Map<String, Object> secretData = Map.of(keyName, base64Data);
      vault.logical().write(name, secretData);
    } catch (VaultException e) {
      throw new IOException("Error writing to Vault", e);
    }
  }

  @Override
  public Store create(Map<String, Object> config) throws IOException {
    String vaultAddress = (String) config.get("vaultAddress");
    String vaultToken = (String) config.get("vaultToken");

    String keyName = "data";
    if(config.containsKey("keyName")){
      keyName = (String) config.get("keyName");
    }

    VaultConfig vaultConfig;
    try {
      vaultConfig = new VaultConfig()
          .address(vaultAddress)
          .token(vaultToken)
          .build();
    } catch (VaultException e) {
      throw new IOException(e);
    }
    Vault vault = new Vault(vaultConfig);
    return new VaultStore(vault, keyName);
  }
}
