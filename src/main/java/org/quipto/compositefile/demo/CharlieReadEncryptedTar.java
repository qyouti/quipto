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

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPException;
import org.quipto.compositefile.EncryptedCompositeFile;
import org.quipto.compositefile.EncryptedCompositeFileUser;
import org.quipto.key.impl.OldPGPFileKeyFinder;
import org.quipto.trust.TrustContext;
import org.quipto.trust.impl.TrustAnythingContext;

/**
 * User Charlie reads an entry in the demo encrypted composite file.
 * 
 * @author maber01
 */
public class CharlieReadEncryptedTar
{

  public static char[] readEncryptedPassword( File file ) 
          throws KeyStoreException
  {
    try
    {
      KeyStore keyStore = KeyStore.getInstance("Windows-MY");
      keyStore.load(null, null);  // Load keystore 
      PrivateKey k = (PrivateKey)keyStore.getKey("My key pair for guarding passwords", null );    

      FileInputStream fin = new FileInputStream( file );
      ByteArrayOutputStream baout = new ByteArrayOutputStream();
      int b;
      while ( (b = fin.read()) >=0  )
        baout.write( b );
      fin.close();
      baout.close();

      Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
      cipher.init( Cipher.DECRYPT_MODE, k );
      byte[] decrypt = cipher.doFinal( baout.toByteArray() );
      System.out.println( "Password is: " + new String( decrypt, "UTF8" ) );
      return new String( decrypt, "UTF8" ).toCharArray();
    }
    catch ( IOException | InvalidKeyException | NoSuchAlgorithmException | UnrecoverableKeyException | CertificateException | BadPaddingException | IllegalBlockSizeException | NoSuchPaddingException e )
    {
      e.printStackTrace();
    }
    return null;
  }
  
  
  /**
   * @param args the command line arguments
   */
  public static void main(String[] args)
  {
    Security.addProvider(new BouncyCastleProvider());
    
    try
    {
      int x, i;
      InputStream in;
      File file = new File("demo/mydataenc.tar");
      File charlieseckeyfile = new File( "demo/charlie_secring.gpg" );
      File charliepubkeyfile = new File( "demo/charlie_pubring.gpg" );
      
      OldPGPFileKeyFinder charliekeyfinder = new OldPGPFileKeyFinder( charlieseckeyfile, charliepubkeyfile );
      charliekeyfinder.init();
      
      TrustContext trustcontext = new TrustAnythingContext();
      EncryptedCompositeFileUser charlie = new EncryptedCompositeFileUser( charliekeyfinder, trustcontext );
      EncryptedCompositeFile compfile = EncryptedCompositeFile.getCompositeFile(file);
      
      in=compfile.getDecryptingInputStream(charlie,"little.txt.gpg");
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
      compfile.close();
      System.out.print( "\n\n" );
    }
    catch (IOException ex)
    {
      Logger.getLogger(BobReadEncryptedTar.class.getName()).log(Level.SEVERE, null, ex);
    } catch (PGPException ex)
    {
      Logger.getLogger(BobReadEncryptedTar.class.getName()).log(Level.SEVERE, null, ex);
    }


  }

}
