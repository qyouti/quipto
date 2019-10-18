/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.quipto.key.impl;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Iterator;
import java.util.Properties;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.bouncycastle.bcpg.sig.NotationData;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.operator.KeyFingerPrintCalculator;
import org.bouncycastle.openpgp.operator.PBESecretKeyDecryptor;
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.bc.BcPBESecretKeyDecryptorBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider;
import org.bouncycastle.util.Arrays;
import org.quipto.QuiptoStandards;
import org.quipto.compositefile.EncryptedCompositeFile;
import org.quipto.key.KeyFinder;
import org.quipto.key.KeyFinderException;

/**
 * An implementation of KeyFinder that loads keys from old style OpenPGP key ring files.
 * @author maber01
 */
public class CompositeFileKeyFinder implements KeyFinder
{
  
  KeyFingerPrintCalculator fpcalc = new BcKeyFingerprintCalculator();
  BcPBESecretKeyDecryptorBuilder seckeydecbuilder = new BcPBESecretKeyDecryptorBuilder(  new BcPGPDigestCalculatorProvider() );
  PBESecretKeyDecryptor keydecryptor = seckeydecbuilder.build( QuiptoStandards.SECRET_KEY_STANDARD_PASS );
          
  CompositeFileKeyStore store;
  String signingalias, encryptingalias;
          
  PGPSecretKey  secretkeyforsigning;
  PGPPrivateKey privatekeyforsigning;

  PGPSecretKey  secretkeyforencrypting;
  PGPPrivateKey privatekeyforencrypting;
  
  /**
   * Construct by referencing files containing KeyRingCollections.
   * 
   * @param tarfile
   */
  public CompositeFileKeyFinder( CompositeFileKeyStore store, String signingalias, String encryptingalias ) throws IOException
  {
    this.store = store;
    this.signingalias = signingalias;
    this.encryptingalias = encryptingalias;
  }

  
  /**
   * Load keys from the files. Also decide which private key is the default for signing and decrypting.
   * 
   * @throws IOException
   * @throws PGPException 
   */
  public void init() throws IOException, PGPException
  {
    PGPSecretKeyRingCollection[] coll = new PGPSecretKeyRingCollection[2];
    PGPSecretKey secretkey;
    PGPPrivateKey privatekey;
    for ( int i=0; i<2; i++ )
    {
      coll[i] = store.getSecretKeyRingCollection( (i==0)?signingalias:encryptingalias );
      secretkey = coll[i].getKeyRings().next().getSecretKey();
      privatekey = secretkey.extractPrivateKey( keydecryptor );
      if ( i==0 )
      {
        secretkeyforsigning = secretkey;
        privatekeyforsigning = privatekey;
      }
      if ( i==1 || signingalias.equals( encryptingalias ) )
      {
        secretkeyforencrypting = secretkey;
        privatekeyforencrypting = privatekey;
        break;
      }
    }
  }


  
  /**
   * Get the first alias associated with the selected private key
   * @param secretkey
   * @return 
   */
  public String getPreferredAlias( PGPSecretKey secretkey )
  {
    Iterator<String> iter = secretkey.getUserIDs();
    if ( iter.hasNext() )
      return iter.next();
    return null;
  }
  
  /**
   * Get the user's currently selected signing key.
   * @param secretkey
   * @return 
   */
  @Override
  public PGPPrivateKey getPrivateKey( PGPSecretKey secretkey )
  {
    if ( secretkey == secretkeyforsigning )
      return privatekeyforsigning;
    return null;
  }
  
  /**
   * Get the user's currently selected decryption key.
   * @return 
   */
  @Override
  public PGPSecretKey getSecretKeyForDecryption()
  {
    return secretkeyforsigning;
  }
  
  /**
   * Get the user's currently selected decryption key.
   * @return 
   */
  @Override
  public PGPSecretKey getSecretKeyForSigning()
  {
    return secretkeyforsigning;    
  }

  /**
   * Search in the public key ring collection for a public key by its keyid.
   * @param keyid
   * @return 
   */
  @Override
  public PGPPublicKey findPublicKey(long keyid)
  {
    PGPPublicKeyRingCollection coll = store.getPublicKeyRingCollection( keyid );
    if ( coll == null ) return null;
    try
    {
      return coll.getPublicKey(keyid);
    }
    catch (PGPException ex)
    {
      Logger.getLogger(CompositeFileKeyFinder.class.getName()).log(Level.SEVERE, null, ex);
    }
    return null;
  }

  /**
   * Also check that the key has the given userid.
   * @param keyid
   * @param userid
   * @return 
   */
  @Override
  public PGPPublicKey findPublicKey(long keyid, String userid)
  {
    PGPPublicKey pubkey = findPublicKey( keyid );
    if ( pubkey == null ) return null;
    Iterator<String> iter = pubkey.getUserIDs();
    while ( iter.hasNext() )
    {
      if ( iter.next().equalsIgnoreCase(userid) )
        return pubkey;
    }
    return null;
  }

  /**
   * Also check the fingerprint
   * @param keyid
   * @param userid
   * @param fingerprint
   * @return
   * @throws KeyFinderException 
   */
  @Override
  public PGPPublicKey findPublicKey(long keyid, String userid, byte[] fingerprint)
          throws KeyFinderException
  {
    PGPPublicKey pubkey = findPublicKey( keyid, userid );
    if ( pubkey == null ) return null;
    byte[] actualfingerprint = pubkey.getFingerprint();
    if ( Arrays.compareUnsigned(actualfingerprint, fingerprint) == 0 )
      return pubkey;
    return null;
  }
  
  /**
   * Find first public key which matches the userid.
   * @param userid
   * @return 
   */
  public PGPPublicKey findFirstPublicKey( String userid )
  {
    PGPPublicKeyRingCollection coll = store.getPublicKeyRingCollection( userid );
    if ( coll == null ) return null;
    PGPPublicKeyRing keyring = coll.getKeyRings().next();
    return keyring.getPublicKeys().next();
  }
}
