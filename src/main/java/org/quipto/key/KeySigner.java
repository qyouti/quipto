/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.quipto.key;

import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;

/**
 *
 * @author maber01
 */
public interface KeySigner
{
  public PGPPublicKey signKey( PGPPrivateKey signingkey, PGPPublicKey publickey, int keyflags, int include );
}
