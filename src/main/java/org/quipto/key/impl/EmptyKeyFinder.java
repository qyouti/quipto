/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.quipto.key.impl;

import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.quipto.key.KeyFinder;
import org.quipto.key.KeyFinderException;

/**
 *
 * @author maber01
 */
public class EmptyKeyFinder implements KeyFinder
{

  @Override
  public String getPreferredAlias(PGPSecretKey secretkey)
  {
    return null;
  }

  @Override
  public PGPPrivateKey getPrivateKey(PGPSecretKey secretkey)
  {
    return null;
  }

  @Override
  public PGPSecretKey getSecretKeyForDecryption()
  {
    return null;
  }

  @Override
  public PGPSecretKey getSecretKeyForSigning()
  {
    return null;
  }

  @Override
  public PGPPublicKey findPublicKey(long keyid)
  {
    return null;
  }

  @Override
  public PGPPublicKey findPublicKey(long keyid, String userid)
  {
    return null;
  }

  @Override
  public PGPPublicKey findPublicKey(long keyid, String userid, byte[] fingerprint)
          throws KeyFinderException
  {
    return null;
  }

  @Override
  public PGPPublicKey findFirstPublicKey(String userid)
  {
    return null;
  }
  
}
