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
public class AliceMakeEncryptedTar
{

  /**
   * @param args the command line arguments
   */
  public static void main(String[] args)
  {
    int i;
    byte[] buffer = "The quick brown fox jumps over the lazy dog. \n".getBytes();

    Security.addProvider(new BouncyCastleProvider());

    try
    {
      File dir = new File( "demo/shared" );
      if ( !dir.exists() )
        dir.mkdir();
      File file = new File(dir, "mydataenc.tar");
      if ( file.exists() )
        file.delete();
      
//      File teamtrustfile = new File("demo/shared/teamtrust.tar");
//      if ( teamtrustfile.exists() )
//        teamtrustfile.delete();      
//      TeamTrust teamtrust = new TeamTrust( teamtrustfile, alicekeyfinder );
//      teamtrust.init();


      String alicealias = "alice";
      EncryptedCompositeFileUser alicekeystoreeu = new EncryptedCompositeFileUser( new PasswordPasswordHandler( "alice@thingy.com", "alice".toCharArray() ) );
      CompositeFileKeyStore keyringstore = new CompositeFileKeyStore( EncryptedCompositeFile.getCompositeFile( new File("demo/alicehome/keyring.tar") ), alicekeystoreeu );
      CompositeFileKeyFinder keyfinder = new CompositeFileKeyFinder( keyringstore, alicealias, alicealias );
      keyfinder.init();
      PGPSecretKey secretkey = keyfinder.getSecretKeyForDecryption();
      PGPPublicKey bobkey = keyfinder.findFirstPublicKey("bob");
      if ( bobkey == null )
        throw new IOException( "Can't find Bob's public key.");
      PGPPublicKey charliekey = keyfinder.findFirstPublicKey("charlie");
      PGPPublicKey debbiekey = keyfinder.findFirstPublicKey("debbie");
      if ( debbiekey == null )
        throw new IOException( "Can't find Debbie's public key.");
      
      EncryptedCompositeFileUser alice = new EncryptedCompositeFileUser( keyfinder, new TrustAnythingContext() );
      EncryptedCompositeFile compfile = EncryptedCompositeFile.getCompositeFile(file);
      compfile.addPublicKey( alice, secretkey.getPublicKey() );
      compfile.addPublicKey( alice, bobkey );
      if ( charliekey != null )
        compfile.addPublicKey( alice, charliekey );
      compfile.addPublicKey( alice, debbiekey );
      
      OutputStream out;
      out = compfile.getEncryptingOutputStream( alice, "bigdatafile.bin.gpg", false, true );
      for (i = 0; i < 202; i++)
        out.write(buffer);
      out.close();

      
      buffer = "Mary had a little lamb, its fleece was white as snow and everywhere that Mary went the lamb was sure to go. \n".getBytes();      
      out = compfile.getEncryptingOutputStream( alice, "little.txt.gpg", false, true );
      out.write(buffer);
      out.close();
      compfile.close();

    } catch (Exception ex)
    {
      ex.printStackTrace();
    }
  }

}
