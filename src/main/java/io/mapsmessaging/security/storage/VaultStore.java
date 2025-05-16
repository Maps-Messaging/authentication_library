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

package io.mapsmessaging.security.storage;
import com.bettercloud.vault.SslConfig;
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

  public VaultStore(){
    vault = null;
    keyName = null;
  }

  public VaultStore(Vault vault, String name) {
    this.vault = vault;
    this.keyName = name;
  }

  @Override
  public String getName() {
    return "Vault";
  }

  @Override
  public boolean exists(String name) {
    try {
      LogicalResponse response = vault.logical().read(keyName+"/"+name);
      if (response == null || response.getData() == null) {
        return false;
      }
      return response.getData() != null && !response.getData().isEmpty();
    } catch (VaultException e) {
      return false;
    }
  }

  @Override
  public byte[] load(String name) throws IOException {
    try {
      LogicalResponse response = vault.logical().read(keyName+"/"+name);
      if (response == null || response.getData() == null) {
        throw new IOException("Secret not found");
      }
      String base64Data = response.getData().get("keystore");
      return Base64.getDecoder().decode(base64Data);
    } catch (VaultException e) {
      throw new IOException("Error reading from Vault", e);
    }
  }

  @Override
  public void save(byte[] data, String name) throws IOException {
    try {
      if(vault == null)return;
      String base64Data = Base64.getEncoder().encodeToString(data);
      Map<String, Object> secretData = Map.of("keystore", base64Data);
      vault.logical().write(keyName+"/"+name, secretData);
    } catch (VaultException e) {
      throw new IOException("Error writing to Vault", e);
    }
  }

  @Override
  public Store create(Map<String, Object> config) throws IOException {
    String vaultAddress = (String) config.get("vaultAddress");
    String vaultToken = (String) config.get("vaultToken");
    boolean sslverify = true;
    if(config.containsKey("sslVerify")){
      sslverify = Boolean.parseBoolean(config.get("sslVerify").toString());
    }
    String key = "data";
    if(config.containsKey("secretEngine")){
      key = (String) config.get("secretEngine");
    }

    VaultConfig vaultConfig;
    try {
      SslConfig sslConfig= new SslConfig()
          .verify(sslverify)
          .build();
      vaultConfig = new VaultConfig()
          .address(vaultAddress)
          .token(vaultToken)
          .sslConfig(sslConfig)
          .engineVersion(2)
          .build();
    } catch (VaultException e) {
      throw new IOException(e);
    }
    Vault v = new Vault(vaultConfig);
    return new VaultStore(v, key);
  }
}
