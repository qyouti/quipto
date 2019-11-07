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
import org.quipto.passwords.PasswordPasswordHandler;

/**
 * Bob will read an entry in the demo encrypted composite file that was created by Alice.
 * @author maber01
 */
public class Demo35DebbieReadEncryptedTar
{
  static String[] filenames = {"bobscontribution.txt","little.txt"};
  
  /**
   * @param args the command line arguments
   */
  public static void main(String[] args)
  {
    Security.addProvider(new BouncyCastleProvider());    
    PasswordPasswordHandler passhandler = new PasswordPasswordHandler( "debbie@thingy.com", "debbie".toCharArray() );
    ReadEncryptedTar.readEncryptedTar( "debbie", passhandler, filenames );      
  }

}
