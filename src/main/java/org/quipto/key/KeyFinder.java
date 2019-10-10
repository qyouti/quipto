/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.quipto.key;

import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSecretKey;

/**
 * An interface for implementations that supply keys on behalf of
 * a user. Implementations will decide where the keys are stored,
 * how they are stored etc.
 * @author maber01
 */
public interface KeyFinder
{
  /** Which of the aliases should be used as the main user id
   * 
   * @param secretkey
   * @return 
   */
  public String getPreferredAlias( PGPSecretKey secretkey );
  
  /**
   * Get the user's currently selected signing key.
   * @return 
   */
  public PGPPrivateKey getPrivateKey( PGPSecretKey secretkey );
  
  /**
   * Get the user's currently selected decryption key.
   * @return 
   */
  public PGPSecretKey getSecretKeyForDecryption();
  
  /**
   * Get the user's currently selected decryption key.
   * @return 
   */
  public PGPSecretKey getSecretKeyForSigning();
  
  /**
   * Find any public key with the right keyid. If multiple found the
   * implementation decides which, if any to return.
   * @param keyid
   * @return 
   */
  public PGPPublicKey findPublicKey( long keyid );

  /**
   * Find any public key which matches the right keyid AND has a userid matching
   * the one provided. If multiple found the implementation decides which, if any
   * to return.
   * @param keyid
   * @param userid
   * @return 
   */
  public PGPPublicKey findPublicKey( long keyid, String userid );
  
  /**
   * Find any public key which matches the right keyid AND has a userid matching
   * the one provided. 
   * @param keyid
   * @param userid
   * @param fingerprint
   * @return 
   * @throws org.quipto.key.KeyFinderException If a key is selected but the fingerprint does not match.
   */
  public PGPPublicKey findPublicKey( long keyid, String userid, byte[] fingerprint ) throws KeyFinderException;
  
  /**
   * Find first public key which matches the userid.
   * @param userid
   * @return 
   */
  public PGPPublicKey findFirstPublicKey( String userid );
  
}
