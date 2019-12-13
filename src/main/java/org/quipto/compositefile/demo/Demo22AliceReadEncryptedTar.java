/*
 * Copyright 2019 Leeds Beckett University.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.quipto.compositefile.demo;

import java.security.Security;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import static org.quipto.compositefile.demo.DemoUtils.ALICE;
import org.quipto.passwords.PasswordPasswordHandler;

/**
 * Alice will read an entry in the demo encrypted composite file that she created.
 * @author maber01
 */
public class Demo22AliceReadEncryptedTar
{
  static String[] filenames = {"little.txt"};

  /**
   * @param args the command line arguments
   */
  public static void main(String[] args)
  {
    Security.addProvider(new BouncyCastleProvider());    
    PasswordPasswordHandler passhandler = new PasswordPasswordHandler(  ALICE.password );
    ReadEncryptedTar.readEncryptedTar( ALICE, passhandler, filenames );
  }

}
