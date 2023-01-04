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

package io.mapsmessaging.sasl;

import com.ongres.stringprep.Profile;
import com.ongres.stringprep.Stringprep;

/**
 * rfc4013 implementation, for more information please see
 * https://www.rfc-editor.org/rfc/rfc4013
 */

public class SaslPrep {

  private static final SaslPrep instance = new SaslPrep();
  private final Profile saslPrep;

  private SaslPrep(){
    saslPrep = Stringprep.getProvider("SASLprep");
  }

  public static SaslPrep getInstance(){
    return instance;
  }

  // Implements RFC rfc4013
  public String stringPrep(String string){
    return saslPrep.prepareStored(string);
  }

}
