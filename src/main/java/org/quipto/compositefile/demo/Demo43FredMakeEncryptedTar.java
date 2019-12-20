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
import org.quipto.compositefile.EncryptedCompositeFile;
import static org.quipto.compositefile.demo.DemoUtils.DEBBIE;
import static org.quipto.compositefile.demo.DemoUtils.FRED;

import org.quipto.passwords.PasswordPasswordHandler;

/**
 * Alice creates an encrypted composite file. She will add herself and Bob to the users
 * who can read it.  If Charlie's key pair was generated he will be added too.  Data is
 * added to the archive.
 * 
 * @author maber01
 */
public class Demo43FredMakeEncryptedTar
{
  static final DemoUtils.DemoUser[] demousers = { DEBBIE };
  static int[] addpermission =  {EncryptedCompositeFile.ALL_PERMISSIONS};
  static String[] filenames = {"big.bin","little.txt"};
  static boolean[] big = {true,false};
  /**
   * @param args the command line arguments
   */
  public static void main(String[] args)
  {
    Security.addProvider(new BouncyCastleProvider());
    PasswordPasswordHandler passhandler = new PasswordPasswordHandler( FRED.password );
    WriteEncryptedTar.ARCHIVEFILENAME = "demo/shared/fred_and_debbie_data.tar";
    WriteEncryptedTar.writeEncryptedTar( FRED, passhandler, demousers, addpermission, filenames, big);
  }

}
