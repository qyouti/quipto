/*
 * Copyright 2019 jon.
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
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.util.ArrayList;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.quipto.QuiptoStandards;
import org.quipto.compositefile.EncryptedCompositeFile;
import org.quipto.compositefile.EncryptedCompositeFileUser;
import org.quipto.key.impl.CompositeFileKeyStore;
import org.quipto.key.impl.StandardRSAKeyBuilderSigner;
import org.quipto.passwords.PasswordPasswordHandler;
import org.quipto.passwords.WindowsPasswordHandler;

/**
 * Generates RSA PGPPublicKey/PGPSecretKey pairs for demos.
 * Charlie uses a Windows key pair to keep his password. All
 * the others need to use a password every time.
 */
public class Demo01UsersGenerateOwnKeys
{
  final String[] aliases = { "alice", "bob", "charlie", "debbie" };

  //CompositeFileKeyStore[] keyringfile = new CompositeFileKeyStore[aliases.length];
  
  private CompositeFileKeyStore createKeyRing( String alias ) throws IOException, PGPException, NoSuchProviderException, NoSuchAlgorithmException
  {
    File dir, file;
    
    EncryptedCompositeFileUser eu;
    dir = new File( "demo/" + alias + "home" );
    if ( !dir.exists() )
      dir.mkdir();
    file = new File( dir, "keyring.tar");
    if ( file.exists() )
      file.delete();
    if ( "charlie".equals( alias) )
    {
      try 
      {
        WindowsPasswordHandler winpasshandler = new WindowsPasswordHandler();
        eu = new EncryptedCompositeFileUser( winpasshandler );
      }
      catch ( KeyStoreException ksex )
      {
        eu = null;
      }
    }
    else
      eu = new EncryptedCompositeFileUser( new PasswordPasswordHandler( alias + "@thingy.com", alias.toCharArray() ) );
    if ( eu != null )
    {
      CompositeFileKeyStore keystore = new CompositeFileKeyStore( EncryptedCompositeFile.getCompositeFile( file ) );
      keystore.setCompositeFileUser( eu );
      keystore.addAccessToCustomUser();  // add access to self
      return keystore;
    }
    return null;
  }
  
  private void storePublicKey( boolean andexport, String alias, CompositeFileKeyStore keystore, PGPPublicKey key ) throws IOException, PGPException
  {
    if ( keystore == null )
      return;
    
    ArrayList<PGPPublicKey> keylist = new ArrayList<>();
    keylist.add(key);
    PGPPublicKeyRing keyring = new PGPPublicKeyRing(keylist);
    keystore.setPublicKeyRing(keyring);
    
    // export
    if ( andexport )
    {
      File file = new File( "demo/" + alias + "home/myselfsignedpublickey.gpg" );
      if ( file.exists() )
        file.delete();
      FileOutputStream fout = new FileOutputStream( file );
      key.encode( fout );
      fout.close();
    }
  }

  private void storeSecretKey( String alias, CompositeFileKeyStore keystore, PGPSecretKey key ) throws IOException, PGPException
  {
    if ( keystore == null )
      return;
    
    ArrayList<PGPSecretKey> keylist = new ArrayList<>();
    keylist.add(key);
    PGPSecretKeyRing keyring = new PGPSecretKeyRing(keylist);
    keystore.setSecretKeyRing(keyring);
    
    storePublicKey( true, alias, keystore, key.getPublicKey() );  
  }

  private void run()
          throws Exception
  {
    Security.addProvider(new BouncyCastleProvider());
    
    StandardRSAKeyBuilderSigner keybuilder = new StandardRSAKeyBuilderSigner();    
    
    for (String alias : aliases)
    {
      CompositeFileKeyStore keystore = createKeyRing(alias);
      if (keystore != null)
      {
        PGPSecretKey secretkey = keybuilder.buildSecretKey(alias, QuiptoStandards.SECRET_KEY_STANDARD_PASS);
        if (secretkey != null)
          storeSecretKey(alias, keystore, secretkey);
        keystore.close();
      }
    }
  }

   
  /**
   * Run the demo.
   * @param args No arguments used.
   * @throws Exception 
   */
  public static void main(
          String[] args)
          throws Exception
  {
    Demo01UsersGenerateOwnKeys inst = new Demo01UsersGenerateOwnKeys();
    inst.run();
  }
}
