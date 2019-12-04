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
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPException;
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
public class ReadEncryptedTar
{

  /**
   * 
   * @param alias
   * @param passhandler
   * @param entrynames
   */
  public static void readEncryptedTar( String alias, EncryptedCompositeFilePasswordHandler passhandler, String[] entrynames )
  {
    Security.addProvider(new BouncyCastleProvider());
    
    try
    {
      int x, i;
      InputStream in;
      File file = new File("demo/shared/mydataenc.tar");
      File personalkeystorefile = new File("demo/" + alias + "home/keyring.tar");
      File teamkeystorefile = new File( "demo/shared/teamkeyring.tar" );
      
      EncryptedCompositeFileUser personaleu = new EncryptedCompositeFileUser( passhandler );
      CompositeFileKeyStore personalkeystore = new CompositeFileKeyStore( personalkeystorefile, personaleu );
      CompositeFileKeyFinder personalkeyfinder = new CompositeFileKeyFinder( personalkeystore, alias, alias );
      personalkeyfinder.init();
      
      TeamTrust teamtrust = new TeamTrust( alias, personalkeystore, personalkeyfinder, teamkeystorefile );
      EncryptedCompositeFileUser eu = new EncryptedCompositeFileUser( teamtrust, teamtrust );
      EncryptedCompositeFile compfile = new EncryptedCompositeFile(file, false, true, eu);
      compfile.initA();
      compfile.initB();
      compfile.addPublicKey( teamtrust.getSecretKeyForDecryption().getPublicKey() );
      
      for ( String entryname : entrynames )
      {
        in=compfile.getDecryptingInputStream( entryname );
        System.out.print( "0  :  " );
        for ( i=0; (x = in.read()) >= 0; i++ )
        {
          if ( x>15 )
            System.out.print( Character.toString((char)x) /*Integer.toHexString(x)*/ );
          else
            System.out.print( "[0x" +Integer.toHexString(x) + "]" );
          if ( i%64 == 63 )
            System.out.print( "\n" +  Integer.toHexString(i+1) + "  :  " );
        }
        in.close();
        System.out.print( "\n\n" );
      }
      compfile.close();
    }
    catch (IOException ex)
    {
      Logger.getLogger(ReadEncryptedTar.class.getName()).log(Level.SEVERE, null, ex);
    } catch (PGPException ex)
    {
      Logger.getLogger(ReadEncryptedTar.class.getName()).log(Level.SEVERE, null, ex);
    }
    catch (NoSuchProviderException ex)
    {
      Logger.getLogger(ReadEncryptedTar.class.getName()).log(Level.SEVERE, null, ex);
    }
    catch (NoSuchAlgorithmException ex)
    {
      Logger.getLogger(ReadEncryptedTar.class.getName()).log(Level.SEVERE, null, ex);
    }

  }

}
