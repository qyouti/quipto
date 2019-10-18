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
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.SignatureException;
import java.util.ArrayList;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPKeyPair;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
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
public class AliceBobCharlieGenKeys
{
  final String[] aliases = { "alice", "bob", "charlie", "debbie" };

  CompositeFileKeyStore[] keyringfile = new CompositeFileKeyStore[aliases.length];
  
  
  private void createKeyRings() throws IOException, PGPException, NoSuchProviderException, NoSuchAlgorithmException
  {
    for ( int i=0; i<aliases.length; i++  )
    {
      File file = new File("demo/" + aliases[i] + "home/keyring.tar");
      if ( file.exists() )
        file.delete();
      EncryptedCompositeFileUser eu;
      if ( "charlie".equals( aliases[i]) )
        eu = new EncryptedCompositeFileUser( new WindowsPasswordHandler() );
      else
        eu = new EncryptedCompositeFileUser( new PasswordPasswordHandler( aliases[i] + "@thingy.com", aliases[i].toCharArray() ) );
      keyringfile[i] = new CompositeFileKeyStore( EncryptedCompositeFile.getCompositeFile( file ), eu );
    }
  }
  
  private void storePublicKey( int i, PGPPublicKey key ) throws IOException, PGPException
  {
    ArrayList<PGPPublicKey> keylist = new ArrayList<>();
    keylist.add(key);
    PGPPublicKeyRing keyring = new PGPPublicKeyRing(keylist);
    ArrayList<PGPPublicKeyRing> ringlist = new ArrayList<>();
    ringlist.add(keyring);
    PGPPublicKeyRingCollection collection = new PGPPublicKeyRingCollection( ringlist );
    keyringfile[i].setPublicKeyRingCollection(collection);
  }

  private void storeSecretKey( int i, PGPSecretKey key ) throws IOException, PGPException
  {
    ArrayList<PGPSecretKey> keylist = new ArrayList<>();
    keylist.add(key);
    PGPSecretKeyRing keyring = new PGPSecretKeyRing(keylist);
    ArrayList<PGPSecretKeyRing> ringlist = new ArrayList<>();
    ringlist.add(keyring);
    PGPSecretKeyRingCollection collection = new PGPSecretKeyRingCollection( ringlist );
    keyringfile[i].setSecretKeyRingCollection(collection);
    storePublicKey( i, key.getPublicKey() );
  }

  private void run()
          throws Exception
  {
    Security.addProvider(new BouncyCastleProvider());

    // Create key rings for all the demo users
    createKeyRings();
    
    StandardRSAKeyBuilderSigner keybuilder = new StandardRSAKeyBuilderSigner();    
    PGPSecretKey[] secretkey = new PGPSecretKey[aliases.length];
    for ( int i=0; i<aliases.length; i++ )
    {
      secretkey[i]    = keybuilder.buildSecretKey( aliases[i], QuiptoStandards.SECRET_KEY_STANDARD_PASS );
      if ( secretkey[i] != null )
        storeSecretKey( i, secretkey[i] );
    }

    // sign and store stuff
    // Alice and Bob trust each other to sign....
    storePublicKey( 0, secretkey[1].getPublicKey() );
    storePublicKey( 1, secretkey[0].getPublicKey() );

    // Alice and Charlie
    storePublicKey( 0, secretkey[2].getPublicKey() );
    storePublicKey( 2, secretkey[0].getPublicKey() );
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
    AliceBobCharlieGenKeys inst = new AliceBobCharlieGenKeys();
    inst.run();
  }
}
