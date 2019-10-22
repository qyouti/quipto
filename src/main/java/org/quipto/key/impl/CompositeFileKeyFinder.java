/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.quipto.key.impl;

import java.io.IOException;
import java.util.Iterator;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.bouncycastle.openpgp.operator.KeyFingerPrintCalculator;
import org.bouncycastle.openpgp.operator.PBESecretKeyDecryptor;
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.bc.BcPBESecretKeyDecryptorBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider;
import org.bouncycastle.util.Arrays;
import org.quipto.QuiptoStandards;
import org.quipto.key.KeyFinder;
import org.quipto.key.KeyFinderException;

/**
 * An implementation of KeyFinder that loads keys from old style OpenPGP key ring files.
 * @author maber01
 */
public class CompositeFileKeyFinder implements KeyFinder
{
  static final int FORSIGNING = 0;
  static final int FORENCRYPTING = 1;
  
  KeyFingerPrintCalculator fpcalc = new BcKeyFingerprintCalculator();
  BcPBESecretKeyDecryptorBuilder seckeydecbuilder = new BcPBESecretKeyDecryptorBuilder(  new BcPGPDigestCalculatorProvider() );
  PBESecretKeyDecryptor keydecryptor = seckeydecbuilder.build( QuiptoStandards.SECRET_KEY_STANDARD_PASS );
          
  CompositeFileKeyStore store;
  
  SecretKeyInformation[] secretkeyinfo = new SecretKeyInformation[2];
          
  
  /**
   * Construct by referencing files containing KeyRingCollections.
   * 
   * @param store
   * @param signingalias
   * @param encryptingalias
   * @throws java.io.IOException
   */
  public CompositeFileKeyFinder( CompositeFileKeyStore store, String signingalias, String encryptingalias ) throws IOException
  {
    this.store = store;
    secretkeyinfo[FORSIGNING] = new SecretKeyInformation();
    secretkeyinfo[FORENCRYPTING] = new SecretKeyInformation();
    secretkeyinfo[FORSIGNING].alias = signingalias;
    secretkeyinfo[FORENCRYPTING].alias = encryptingalias;
  }

  
  /**
   * Load keys from the files. Also decide which private key is the default for signing and decrypting.
   * 
   * @throws IOException
   * @throws PGPException 
   */
  public void init() throws IOException, PGPException
  {
    PGPSecretKeyRing[] keyrings = new PGPSecretKeyRing[2];
    for ( int i=FORSIGNING; i<=FORENCRYPTING; i++ )
    {
      if ( secretkeyinfo[i].alias != null )
      {
        keyrings[i] = store.getSecretKeyRing( secretkeyinfo[i].alias );
        if ( keyrings[i] != null )
        {
          secretkeyinfo[i].secretkey = CompositeFileKeyStore.getMasterSecretKey(keyrings[i]);
          if ( secretkeyinfo[i].secretkey != null )
          {
            //System.out.println( "Extracting private key " );
            secretkeyinfo[i].privatekey = secretkeyinfo[i].secretkey.extractPrivateKey( keydecryptor );
            if ( i==FORSIGNING && secretkeyinfo[FORSIGNING].alias.equals( secretkeyinfo[FORENCRYPTING].alias ) )
            {
              secretkeyinfo[FORENCRYPTING].secretkey = secretkeyinfo[FORSIGNING].secretkey;
              secretkeyinfo[FORENCRYPTING].privatekey = secretkeyinfo[FORSIGNING].privatekey;
              break;
            }
          }
        }
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
    if ( secretkey == secretkeyinfo[FORSIGNING].secretkey )
      return secretkeyinfo[FORSIGNING].privatekey;
    return null;
  }
  
  /**
   * Get the user's currently selected decryption key.
   * @return 
   */
  @Override
  public PGPSecretKey getSecretKeyForDecryption()
  {
    return secretkeyinfo[FORENCRYPTING].secretkey;
  }
  
  /**
   * Get the user's currently selected decryption key.
   * @return 
   */
  @Override
  public PGPSecretKey getSecretKeyForSigning()
  {
    return secretkeyinfo[FORSIGNING].secretkey;
  }

  /**
   * Search in the public key ring collection for a public key by its keyid.
   * @param keyid
   * @return 
   */
  @Override
  public PGPPublicKey findPublicKey(long keyid)
  {
    PGPPublicKeyRing keyring = store.getPublicKeyRing( keyid );
    if ( keyring == null ) return null;
    return keyring.getPublicKey(keyid);
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
    PGPPublicKeyRing keyring = store.getPublicKeyRing( userid );
    if ( keyring == null ) return null;
    Iterator<PGPPublicKey> iter = keyring.getPublicKeys();
    while ( iter.hasNext() )
    {
      PGPPublicKey key = iter.next();
      Iterator<String> uiter = key.getUserIDs();
      while ( uiter.hasNext() )
        if ( uiter.next().equals(userid ) )
          return key;
    }
    return null;
  }
  
  private class SecretKeyInformation
  {
    String alias;
    PGPSecretKey  secretkey;
    PGPPrivateKey privatekey;
  }
}
