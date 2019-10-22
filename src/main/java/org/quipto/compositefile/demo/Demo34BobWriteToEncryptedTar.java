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

import java.io.File;
import java.io.IOException;
import java.io.OutputStream;
import java.security.Security;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.quipto.compositefile.EncryptedCompositeFile;
import org.quipto.compositefile.EncryptedCompositeFileUser;
import org.quipto.key.impl.CompositeFileKeyFinder;
import org.quipto.key.impl.CompositeFileKeyStore;
import org.quipto.passwords.PasswordPasswordHandler;
import org.quipto.trust.impl.TrustAnythingContext;

/**
 * Alice creates an encrypted composite file. She will add herself and Bob to the users
 * who can read it.  If Charlie's key pair was generated he will be added too.  Data is
 * added to the archive.
 * 
 * @author maber01
 */
public class Demo34BobWriteToEncryptedTar
{

  /**
   * @param args the command line arguments
   */
  public static void main(String[] args)
  {

    Security.addProvider(new BouncyCastleProvider());

    try
    {
      File file = new File("demo/shared/mydataenc.tar");

      String alias = "bob";
      EncryptedCompositeFileUser keystoreeu = new EncryptedCompositeFileUser( new PasswordPasswordHandler( "bob@thingy.com", "bob".toCharArray() ) );
      CompositeFileKeyStore keyringstore = new CompositeFileKeyStore( EncryptedCompositeFile.getCompositeFile( new File("demo/bobhome/keyring.tar") ), keystoreeu );
      CompositeFileKeyFinder keyfinder = new CompositeFileKeyFinder( keyringstore, alias, alias );
      keyfinder.init();
      
      EncryptedCompositeFileUser eu = new EncryptedCompositeFileUser( keyfinder, new TrustAnythingContext() );
      EncryptedCompositeFile compfile = EncryptedCompositeFile.getCompositeFile(file);
      
      OutputStream out;
      
      byte[] buffer = "Mary had a little lamb, its fleece was white as snow and everywhere that Mary went the lamb was sure to go. \n".getBytes();      
      out = compfile.getEncryptingOutputStream( eu, "bobs contribution.txt.gpg", false, true );
      out.write(buffer);
      out.close();
      compfile.close();

    } catch (Exception ex)
    {
      ex.printStackTrace();
    }
  }

}
