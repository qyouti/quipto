/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.quipto.key;

import org.bouncycastle.openpgp.PGPSecretKey;

/**
 * This interface represents a class which is capable of creating quipto compatible OpenPGP
 * key pairs.
 * @author maber01
 */
public interface KeyBuilder
{
  /**
   * Build a key pair.
   * @param userid
   * @param passphrase
   * @param windowsprotection
   * @return 
   */
  public PGPSecretKey buildSecretKey( String userid, char[] passphrase, boolean windowsprotection );
}
