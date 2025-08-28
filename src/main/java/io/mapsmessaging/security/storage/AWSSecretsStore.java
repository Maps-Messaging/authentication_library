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

import java.io.IOException;
import java.util.Base64;
import java.util.Map;
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.AwsCredentialsProvider;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.secretsmanager.SecretsManagerClient;
import software.amazon.awssdk.services.secretsmanager.SecretsManagerClientBuilder;
import software.amazon.awssdk.services.secretsmanager.model.GetSecretValueRequest;
import software.amazon.awssdk.services.secretsmanager.model.GetSecretValueResponse;
import software.amazon.awssdk.services.secretsmanager.model.PutSecretValueRequest;

public class AWSSecretsStore implements Store {

  private final SecretsManagerClient secretsManagerClient;

  public AWSSecretsStore(){
    secretsManagerClient = null;
  }

  public AWSSecretsStore(SecretsManagerClient secretsManagerClient) {
    this.secretsManagerClient = secretsManagerClient;
  }



  @Override
  public String getName() {
    return "AwsSecrets";
  }

  @Override
  public boolean exists(String name) {
    return false;
  }

  @Override
  public byte[] load(String name) throws IOException {
    GetSecretValueRequest getSecretValueRequest = GetSecretValueRequest.builder()
        .secretId(name)
        .build();
    GetSecretValueResponse getSecretValueResponse = secretsManagerClient.getSecretValue(getSecretValueRequest);
    // Assuming the secret is stored as a plain string, not in Base64 in this corrected context
    String secretString = getSecretValueResponse.secretString();
    return Base64.getDecoder().decode(secretString);
  }

  @Override
  public void save(byte[] data, String name) throws IOException {
    String secretString = Base64.getEncoder().encodeToString(data);
    secretsManagerClient.putSecretValue(PutSecretValueRequest.builder()
        .secretId(name)
        .secretString(secretString)
        .build());
  }


  @Override
  public Store create(Map<String, Object> config) throws IOException{
    String region = (String) config.getOrDefault("region", "us-east-1");
    SecretsManagerClientBuilder builder = SecretsManagerClient.builder()
        .region(Region.of(region));

    if (config.containsKey("accessKeyId") && config.containsKey("secretAccessKey")) {
      String accessKeyId = (String) config.get("accessKeyId");
      String secretAccessKey = (String) config.get("secretAccessKey");
      AwsCredentialsProvider credentialsProvider = StaticCredentialsProvider.create(
          AwsBasicCredentials.create(accessKeyId, secretAccessKey));
      builder.credentialsProvider(credentialsProvider);
    }

    // Correctly constructing and returning an AWSSecretsStore instance
    SecretsManagerClient client = builder.build();
    return new AWSSecretsStore(client);
  }
}