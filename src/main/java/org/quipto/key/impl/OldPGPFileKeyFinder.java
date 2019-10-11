/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.quipto.key.impl;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.util.Iterator;
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
import org.quipto.key.KeyFinder;
import org.quipto.key.KeyFinderException;

/**
 * An implementation of KeyFinder that loads keys from old style OpenPGP key ring files.
 * @author maber01
 */
public class OldPGPFileKeyFinder implements KeyFinder
{
  File secfile, pubfile;
  PGPSecretKeyRingCollection secringcoll;
  PGPPublicKeyRingCollection pubringcoll;
  KeyFingerPrintCalculator fpcalc = new BcKeyFingerprintCalculator();
  BcPBESecretKeyDecryptorBuilder seckeydecbuilder = new BcPBESecretKeyDecryptorBuilder(  new BcPGPDigestCalculatorProvider() );

  PGPSecretKey  secretkeyforsigning;
  PGPPrivateKey privatekeyforsigning;
  
  private char[] passphrase;
  
  /**
   * Construct by referencing files containing KeyRingCollections.
   * 
   * @param secfile
   * @param pubfile 
   */
  public OldPGPFileKeyFinder( File secfile, File pubfile )
  {
    this.secfile = secfile;
    this.pubfile = pubfile;
  }

  /**
   * Set a passphrase that will be used to decrypt private keys from the secret key ring.
   * Null passphrase can be used if a Windows key pair is used to protect the password.
   * 
   * @param passphrase 
   */
  public void setPassphrase( char[] passphrase )
  {
    if ( passphrase == null )
      this.passphrase = null;
    else
      this.passphrase = Arrays.clone(passphrase);
  }
  
  /**
   * Load keys from the files. Also decide which private key is the default for signing and decrypting.
   * 
   * @throws IOException
   * @throws PGPException 
   */
  public void init() throws IOException, PGPException
  {
    FileInputStream fin;
    if ( secfile != null )
    {
      fin = new FileInputStream( secfile );
      secringcoll = new PGPSecretKeyRingCollection( fin, fpcalc );
    }
    if ( pubfile != null )
    {
      fin = new FileInputStream( pubfile );
      pubringcoll = new PGPPublicKeyRingCollection( fin, fpcalc );
    }
    
    // use first key in secringcoll as user's selected signing/decryption key
    Iterator<PGPSecretKeyRing> keyringiter = secringcoll.getKeyRings();
    if ( !keyringiter.hasNext() )
      throw new IOException( "The given secret key ring file is empty." );
    PGPSecretKeyRing keyring = keyringiter.next();
    secretkeyforsigning = keyring.getSecretKey();
    privatekeyforsigning = loadPrivateKey( secretkeyforsigning );
  }

  /**  
   * Load the encrypted private key either with a supplied password or using the 
   * Windows encrypted password stored in the public key's signature.
   * @param secretkey
   * @return
   * @throws PGPException 
   */
  private PGPPrivateKey loadPrivateKey( PGPSecretKey secretkey ) throws PGPException
  {
    char[] effectivepassphrase = passphrase;
    Iterator<PGPSignature> sigiter = secretkey.getPublicKey().getSignatures();
    PGPSignature sig;
    NotationData[] notdataarray;
    while ( sigiter.hasNext() )
    {
      sig = sigiter.next();
      notdataarray = sig.getHashedSubPackets().getNotationDataOccurrences();
      String strencryptedpass=null;
      String alias=null;
      for ( NotationData notdata : notdataarray )
      {
        if ( QuiptoStandards.NOTATION_NAME_ENCRYPTED_PASSPHRASE.equals( notdata.getNotationName() ) )
          strencryptedpass=notdata.getNotationValue();
        if ( QuiptoStandards.NOTATION_NAME_WINDOWS_ALIAS.equals( notdata.getNotationName() ) )
          alias=notdata.getNotationValue();
      }
      if ( strencryptedpass != null && alias != null )
      {
        effectivepassphrase = StandardRSAKeyBuilder.decryptWindowsPassphrase(alias, strencryptedpass );
        break;
      }
    }
    PBESecretKeyDecryptor dec = seckeydecbuilder.build(effectivepassphrase);
    return secretkey.extractPrivateKey(dec);
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
    try
    {
      return pubringcoll.getPublicKey(keyid);
    }
    catch (PGPException ex)
    {
      Logger.getLogger(OldPGPFileKeyFinder.class.getName()).log(Level.SEVERE, null, ex);
      return null;
    }
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
    try
    {
      Iterator<PGPPublicKeyRing> keyringiter = pubringcoll.getKeyRings(userid);      
      PGPPublicKeyRing keyring;
      Iterator<PGPPublicKey> keyiter;
      PGPPublicKey pubkey;
      Iterator<String> iter;
      String founduserid;
      while ( keyringiter.hasNext() )
      {
        keyring = keyringiter.next();
        keyiter = keyring.getPublicKeys();
        while ( keyiter.hasNext() )
        {
          pubkey = keyiter.next();
          iter = pubkey.getUserIDs();
          while ( iter.hasNext())
          {
            founduserid = iter.next();
            if ( userid.equals( founduserid ) )
              return pubkey;
          }
        }
      }
      return null;
    }
    catch (PGPException ex)
    {
      Logger.getLogger(OldPGPFileKeyFinder.class.getName()).log(Level.SEVERE, null, ex);
      return null;
    }
  }
}
