/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.quipto.trust.impl;

import org.bouncycastle.openpgp.PGPPublicKey;
import org.quipto.trust.TrustContext;
import org.quipto.trust.TrustContextReport;

/**
 * Another silly implementation that trusts no public key.
 * 
 * @author maber01
 */
public class TrustNothingContext implements TrustContext
{
  /**
   * Is the public key trusted - no, never!
   * @param pubkey
   * @return 
   */
  @Override
  public TrustContextReport checkTrusted(PGPPublicKey pubkey)
  {
    if ( pubkey == null )
      return new TrustContextReport( false, "Empty key cannot be trusted to sign data files." );
    return new TrustContextReport( false, "Not trusted because a 'trust nothing' setting was selected." );
  }
  
}
