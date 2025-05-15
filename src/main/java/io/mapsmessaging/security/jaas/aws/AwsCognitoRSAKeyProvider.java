/*
 *
 *  Copyright [ 2020 - 2024 ] [Matthew Buckton]
 *  Copyright [ 2024 - 2025 ] [Maps Messaging B.V.]
 *
 *   Licensed under the Apache License, Version 2.0 (the "License");
 *   you may not use this file except in compliance with the License.
 *   You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */

package io.mapsmessaging.security.jaas.aws;

import static io.mapsmessaging.security.logging.AuthLogMessages.AWS_INVALID_URL;
import static io.mapsmessaging.security.logging.AuthLogMessages.AWS_KEY_LOAD_FAILURE;

import com.auth0.jwk.JwkException;
import com.auth0.jwk.JwkProvider;
import com.auth0.jwk.JwkProviderBuilder;
import com.auth0.jwt.interfaces.RSAKeyProvider;
import io.mapsmessaging.logging.Logger;
import io.mapsmessaging.logging.LoggerFactory;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

public class AwsCognitoRSAKeyProvider implements RSAKeyProvider {

  private final Logger logger = LoggerFactory.getLogger(AwsCognitoRSAKeyProvider.class);
  private final URL awsKidStoreUrl;
  private final JwkProvider provider;

  public AwsCognitoRSAKeyProvider(String awsCognitoRegion, String awsUserPoolsId) throws IOException {
    String url = String.format("https://cognito-idp.%s.amazonaws.com/%s/.well-known/jwks.json", awsCognitoRegion, awsUserPoolsId);
    try {
      awsKidStoreUrl = URI.create(url).toURL();
      provider = new JwkProviderBuilder(awsKidStoreUrl).build();
    } catch (MalformedURLException e) {
      logger.log(AWS_INVALID_URL, url);
      throw new IOException(e);
    }
  }


  @Override
  public RSAPublicKey getPublicKeyById(String kid) {
    try {
      return (RSAPublicKey) provider.get(kid).getPublicKey();
    } catch (JwkException e) {
      logger.log(AWS_KEY_LOAD_FAILURE, kid, awsKidStoreUrl);
    }
    return null;
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