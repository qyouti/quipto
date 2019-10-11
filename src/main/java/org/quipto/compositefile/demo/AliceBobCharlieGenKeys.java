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

import java.io.FileOutputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.SignatureException;
import java.util.ArrayList;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.quipto.key.impl.StandardRSAKeyBuilder;

/**
 * Generates RSA PGPPublicKey/PGPSecretKey pairs for demos.
 * Alice and Bob get PGP key pairs stored in their secret key rings. The
 * two public keys are put into Alice, Bob and Charlie's public key rings.
 * (Charlie will use Windows CAPI for his key pair.)
 */
public class AliceBobCharlieGenKeys
{

  PGPSecretKeyRingCollection[] secringcoll = new PGPSecretKeyRingCollection[3];
  PGPPublicKeyRingCollection[] pubringcoll = new PGPPublicKeyRingCollection[3];
  
  String[] aliases = { "alice", "bob", "charlie" };
  
  private void createKeyRings() throws IOException, PGPException
  {
    secringcoll[0] = new PGPSecretKeyRingCollection( new ArrayList<>() );
    secringcoll[1] = new PGPSecretKeyRingCollection( new ArrayList<>() );
    secringcoll[2] = new PGPSecretKeyRingCollection( new ArrayList<>() );
    
    pubringcoll[0] = new PGPPublicKeyRingCollection( new ArrayList<>() );
    pubringcoll[1] = new PGPPublicKeyRingCollection( new ArrayList<>() );    
    pubringcoll[2] = new PGPPublicKeyRingCollection( new ArrayList<>() );    
  }
  
  
  private void saveKeyRings() throws IOException
  {
    FileOutputStream out;
    
    for ( int i=0; i<aliases.length; i++ )
    {
      if ( secringcoll[i] != null )
      {
        out = new FileOutputStream("demo/" + aliases[i] + "_secring.gpg");
        secringcoll[i].encode(out);
        out.close();
      }

      out = new FileOutputStream("demo/" + aliases[i] + "_pubring.gpg");
      pubringcoll[i].encode(out);
      out.close();
    }
  }
  
  
  private void storeKeyPair( int secretOut, PGPSecretKey secretKey)
          throws IOException, InvalidKeyException, NoSuchProviderException, SignatureException, PGPException
  {
    PGPPublicKey key = secretKey.getPublicKey();

    ArrayList<PGPSecretKey> seckeylist = new ArrayList<>();
    seckeylist.add(secretKey);
    PGPSecretKeyRing secretKeyRing = new PGPSecretKeyRing(seckeylist);

    ArrayList<PGPPublicKey> keylist = new ArrayList<>();
    keylist.add(key);
    PGPPublicKeyRing keyring = new PGPPublicKeyRing(keylist);
    
    // add secret stuff to own
    secringcoll[secretOut] = PGPSecretKeyRingCollection.addSecretKeyRing( secringcoll[secretOut], secretKeyRing );
    // add public to all
    for ( int i=0; i<pubringcoll.length; i++ )
      pubringcoll[i] = PGPPublicKeyRingCollection.addPublicKeyRing( pubringcoll[i], keyring );
  }


  private void run()
          throws Exception
  {
    Security.addProvider(new BouncyCastleProvider());

    StandardRSAKeyBuilder keybuilder = new StandardRSAKeyBuilder();
    
    PGPSecretKey aliceseckey    = keybuilder.buildSecretKey( "alice",  "alice".toCharArray(), false );
    PGPSecretKey bobseckey      = keybuilder.buildSecretKey( "bob",      "bob".toCharArray(), false );
    PGPSecretKey charlieseckey  = keybuilder.buildSecretKey( "charlie", null,                 true  );
    
    // Create key rings for all the demo users
    createKeyRings();
    // Put keys pairs in OpenPGP format and put in OpenPGP key rings
    storeKeyPair( 0, aliceseckey );
    storeKeyPair( 1, bobseckey );
    // Do charlie's keys if created
    if ( charlieseckey != null )
      storeKeyPair( 2, charlieseckey );
    
    // Save the key rings to files
    saveKeyRings();
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
