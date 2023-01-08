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

import com.auth0.jwk.JwkException;
import com.auth0.jwk.JwkProvider;
import com.auth0.jwk.JwkProviderBuilder;
import com.auth0.jwt.interfaces.RSAKeyProvider;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

public class AwsCognitoRSAKeyProvider implements RSAKeyProvider {

  private final URL awsKidStoreUrl;
  private final JwkProvider provider;

  public AwsCognitoRSAKeyProvider(String awsCognitoRegion, String awsUserPoolId) throws MalformedURLException {
    String url = String.format("https://cognito-idp.%s.amazonaws.com/%s/.well-known/jwks.json", awsCognitoRegion, awsUserPoolId);
    awsKidStoreUrl = new URL(url);
    provider = new JwkProviderBuilder(awsKidStoreUrl).build();
  }
  
  @Override
  public RSAPublicKey getPublicKeyById(String kid) {
    try {
      return (RSAPublicKey) provider.get(kid).getPublicKey();
    } catch (JwkException e) {
      throw new RuntimeException(String.format("Failed to get JWT kid=%s from aws_kid_store_url=%s", kid, awsKidStoreUrl));
    }
  }

  @Override
  public RSAPrivateKey getPrivateKey() {
    return null;
  }

  @Override
  public String getPrivateKeyId() {
    return null;
  }
}
