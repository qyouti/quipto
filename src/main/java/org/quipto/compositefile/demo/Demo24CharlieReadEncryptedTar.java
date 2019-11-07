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

import java.security.KeyStoreException;
import java.security.Security;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.quipto.passwords.WindowsPasswordHandler;

/**
 * User Charlie reads an entry in the demo encrypted composite file that Alice made.
 * 
 * @author maber01
 */
public class Demo24CharlieReadEncryptedTar
{
  static String[] filenames = {"little.txt"};
  /**
   * @param args the command line arguments
   */
  public static void main(String[] args) throws KeyStoreException
  {
    Security.addProvider(new BouncyCastleProvider());

    WindowsPasswordHandler passhandler = new WindowsPasswordHandler();
    ReadEncryptedTar.readEncryptedTar( "charlie", passhandler, filenames );
  }

}
