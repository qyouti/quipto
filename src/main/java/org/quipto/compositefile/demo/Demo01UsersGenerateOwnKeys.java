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
 * Alice and Bob get PGP key pairs stored in their secret key rings. The
 * two public keys are put into Alice, Bob and Charlie's public key rings.
 * (Charlie will use Windows CAPI for his key pair.)
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
      return new CompositeFileKeyStore( EncryptedCompositeFile.getCompositeFile( file ), eu );
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
    File dir = new File( "demo/shared" );
    if ( !dir.exists() )
      dir.mkdir();
    
    File file = new File( dir, "teamkeyring.tar");
    if ( file.exists() )
      file.delete();
    
    Security.addProvider(new BouncyCastleProvider());

    
    StandardRSAKeyBuilderSigner keybuilder = new StandardRSAKeyBuilderSigner();    
    PGPSecretKey[] secretkey = new PGPSecretKey[aliases.length];
    for ( int i=0; i<aliases.length; i++ )
    {
      CompositeFileKeyStore keystore = createKeyRing( aliases[i] );
      if ( keystore != null )
      {
        secretkey[i]    = keybuilder.buildSecretKey( aliases[i], QuiptoStandards.SECRET_KEY_STANDARD_PASS );
        if ( secretkey[i] != null )
          storeSecretKey( aliases[i], keystore, secretkey[i] );
        keystore.close();
      }
    }

    // sign and store stuff
    // Alice and Bob trust each other to sign....
    //storePublicKey( 0, secretkey[1].getPublicKey() );
    //storePublicKey( 1, secretkey[0].getPublicKey() );

    // Alice and Charlie
    //if ( keyringfile[2] != null )
    //{
    //  storePublicKey( 0, secretkey[2].getPublicKey() );
    //  storePublicKey( 2, secretkey[0].getPublicKey() );
    //}
    
    // Alice and Debbie
//    storePublicKey( 0, secretkey[3].getPublicKey() );
//    storePublicKey( 3, secretkey[0].getPublicKey() );
    
    
//    PasswordPasswordHandler passhandler = new PasswordPasswordHandler( aliases[0] + "@thingy.com", aliases[0].toCharArray() );
//    TeamTrust teamtrust = new TeamTrust( aliases[0], passhandler, new File( "demo/" + aliases[0] + "home/keyring.tar" ), file );
//    
//    PGPSecretKey alicesecretkey = teamtrust.getSecretKeyForSigning();
//    PGPPrivateKey aliceprivatekey = teamtrust.getPrivateKey(alicesecretkey);
//    PGPPublicKey alicesignedbob = keybuilder.signKey( aliceprivatekey, secretkey[1].getPublicKey(),  KeyFlags.SIGN_DATA|KeyFlags.ENCRYPT_STORAGE|KeyFlags.CERTIFY_OTHER);
//    
//    for ( int i=0; i<aliases.length; i++  )
//      teamtrust.addPublicKeyToTeam( secretkey[i].getPublicKey() );
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
