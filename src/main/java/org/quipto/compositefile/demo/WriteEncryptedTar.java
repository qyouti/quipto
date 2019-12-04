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
import java.io.InputStream;
import java.io.OutputStream;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.quipto.compositefile.EncryptedCompositeFile;
import org.quipto.compositefile.EncryptedCompositeFilePasswordHandler;
import org.quipto.compositefile.EncryptedCompositeFileUser;
import org.quipto.key.impl.CompositeFileKeyFinder;
import org.quipto.key.impl.CompositeFileKeyStore;
import org.quipto.trust.team.TeamTrust;

/**
 * Bob will read an entry in the demo encrypted composite file that was created by Alice.
 * @author maber01
 */
public class WriteEncryptedTar
{

  /**
   * 
   * @param alias
   * @param passhandler
   * @param addalias
   * @param addpermission
   * @param entrynames
   * @param big
   */
  public static void writeEncryptedTar( 
          String alias, 
          EncryptedCompositeFilePasswordHandler passhandler, 
          String[] addalias,
          int[] addpermission,
          String[] entrynames, 
          boolean[] big )
  {
    Security.addProvider(new BouncyCastleProvider());
    
    try
    {
      int repeats;
      byte[] buffer;
      File file = new File("demo/shared/mydataenc.tar");
      File personalkeystorefile = new File("demo/" + alias + "home/keyring.tar");
      File teamkeystorefile = new File( "demo/shared/teamkeyring.tar" );
      
      EncryptedCompositeFileUser personaleu = new EncryptedCompositeFileUser( passhandler );
      CompositeFileKeyStore personalkeystore = new CompositeFileKeyStore( personalkeystorefile, personaleu );
      CompositeFileKeyFinder personalkeyfinder = new CompositeFileKeyFinder( personalkeystore, alias, alias );
      personalkeyfinder.init();
      
      TeamTrust teamtrust = new TeamTrust( alias, personalkeystore, personalkeyfinder, teamkeystorefile );      
      EncryptedCompositeFileUser eu = new EncryptedCompositeFileUser( teamtrust, teamtrust );
      EncryptedCompositeFile compfile = new EncryptedCompositeFile( file, !file.exists(), true, eu );
      compfile.initA();      
      compfile.initB();
      
      for ( int i=0; i<addalias.length; i++ )
      {
        PGPPublicKey addkey = teamtrust.findFirstPublicKey( addalias[i] );
        if ( addkey != null )
        {
          compfile.addPublicKey( addkey );
          compfile.setPermission( addkey, addpermission[i] );
        }
      }
      
      for ( int j=0; j<entrynames.length; j++ )
      {
        String entryname = entrynames[j];
        OutputStream out = compfile.getEncryptingOutputStream( entryname, true, true );
        if ( big[j] )
        {
          buffer = "The quick brown fox jumps over the lazy dog. \n".getBytes();
          repeats = 100;
        }
        else
        {
          buffer = "Mary had a little lamb, its fleece was white as snow and everywhere that Mary went the lamb was sure to go. \n".getBytes();
          repeats = 1;
        }
        for ( int i=0; i<repeats; i++ )
          out.write(buffer);
        out.close();
      }
      compfile.close();
    }
    catch (IOException | PGPException | NoSuchProviderException | NoSuchAlgorithmException ex)
    {
      Logger.getLogger(WriteEncryptedTar.class.getName()).log(Level.SEVERE, null, ex);
    }

  }

}
